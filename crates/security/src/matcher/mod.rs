//! Match a rule against the workspace's browse facts.
//!
//! The matcher is **purely fact-level**: it never walks the tracer, never
//! builds chains, and never calls the resolver directly. Call-chain
//! enumeration and taint filtering are the job of `bonsai_inspect` via
//! [`crate::compile`]. The matcher just tells callers *which facts* in the
//! workspace look like a source / sink / sanitizer.

use crate::rule::{
    ArgTaintedSpec, ConstraintKind, LifecycleBindingTarget, MatchKind, MatchOrigin,
    ReceiverFactoryArgumentsSpec, ReceiverOriginCallbackParamReachesCallSpec, Rule, RuleBindingOrigin,
    RuleTarget,
};
use ahash::{AHashMap, AHashSet};
use aho_corasick::AhoCorasick;
use bonsai_common::{qualified_names_match, FileId, Span, SymbolId};
use bonsai_hash::Hasher as StableHasher;
use bonsai_index::GlobalIndex;
use bonsai_lang_api::{
    AliasTarget, AssignValueKind, AssignmentValueIndex, CallArg, CallKind, CallTextPrefilter,
    CompilerAssignmentAlias, CompilerSyntaxHeader, Decl, DeclIndex, DeclKind, FlowEvent, ImportSpec,
    ModulePath, RefKind, TypeAliasBinding,
};
use bonsai_taint::{TaintedCall, TaintedCallKind};
use bonsai_workspace::{decl_decorator_names, Workspace};
use lru::LruCache;
use regex::Regex;
use std::{
    cell::RefCell,
    hash::Hash,
    sync::{
        atomic::{AtomicU64, AtomicUsize, Ordering},
        mpsc, Arc, OnceLock,
    },
    time::Instant,
};

const LOCAL_IMPORT_PACKAGE_PREFIX: &str = "__bonsai_local_import_pkg__";
const LOCAL_IMPORT_PACKAGE_SIGNAL_PREFIX: &str = "__bonsai_local_import_pkg_signal__";
const WORKSPACE_IMPORT_PACKAGE_PREFIX: &str = "__bonsai_workspace_import_pkg__";
const COMPONENT_IMPORT_PACKAGE_PREFIX: &str = "__bonsai_component_import_pkg__";
const MANIFEST_PACKAGE_PREFIX: &str = "__bonsai_manifest_pkg__";
const TEMPLATE_MANIFEST_PACKAGE_PREFIX: &str = "__bonsai_template_manifest_pkg__";
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
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
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
        let arg = args.get(index);
        // Hot path: span-equality lookup against pre-binned calls.
        if self.calls_by_span.get(&span).is_some_and(|calls| {
            calls
                .iter()
                .any(|call| tainted_call_has_arg(call, index, arg, true, allow_synthetic_write))
        }) {
            return true;
        }
        // Fallback: overlap-only check for cross-line / multi-call
        // expressions where the matcher and engine spans diverge.
        self.calls.iter().any(|call| {
            spans_overlap(span, call.call_span)
                && tainted_call_has_arg(call, index, arg, false, allow_synthetic_write)
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
    /// APIs such as Scala `tainted.!`, where the dangerous operand is not a
    /// syntactic argument.
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
/// (when index-matching is allowed) OR an arg/receiver whose compiler-lowered
/// place or value carriers intersect the syntactic argument's compiler facts.
fn tainted_call_has_arg(
    call: &TaintedCall,
    index: usize,
    arg: Option<&CallArg>,
    allow_index_match: bool,
    allow_synthetic_write: bool,
) -> bool {
    if call.kind != TaintedCallKind::Call && !(allow_synthetic_write && call.kind == TaintedCallKind::Write) {
        return false;
    }
    call.tainted_args.iter().any(|tainted| {
        (allow_index_match && tainted.index == index)
            || arg.is_some_and(|arg| arg_matches_tainted_value(arg, tainted))
    }) || call.tainted_receiver.as_deref().is_some_and(|receiver| {
        arg.is_some_and(|arg| {
            arg_matches_tainted_receiver(arg, receiver, &call.tainted_receiver_source_names)
        })
    })
}

/// Compare one matcher argument with one engine-recorded tainted argument by
/// intersecting their adapter-lowered place/value-carrier identities.
fn arg_matches_tainted_value(arg: &CallArg, tainted: &bonsai_taint::TaintedArgAtCall) -> bool {
    structured_argument_names(arg).any(|candidate| {
        tainted_argument_names(tainted).any(|value| compiler_value_names_match(candidate, value))
    })
}

/// True when an argument shares an exact adapter-lowered carrier with a
/// tainted receiver. Receiver source names cover compound projections such as
/// `req.body`; no rendered expression text is parsed here.
fn arg_matches_tainted_receiver(arg: &CallArg, receiver: &str, receiver_sources: &[String]) -> bool {
    structured_argument_names(arg).any(|candidate| {
        std::iter::once(receiver)
            .chain(receiver_sources.iter().map(String::as_str))
            .any(|value| compiler_value_names_match(candidate, value))
    })
}

fn structured_argument_names(arg: &CallArg) -> impl Iterator<Item = &str> {
    arg.place
        .as_deref()
        .into_iter()
        .chain(arg.source_names.iter().map(String::as_str))
}

fn tainted_argument_names(arg: &bonsai_taint::TaintedArgAtCall) -> impl Iterator<Item = &str> {
    arg.place
        .as_deref()
        .into_iter()
        .chain(arg.source_names.iter().map(String::as_str))
}

/// Compare two values that adapters have already classified as compiler
/// names/places. They originate in one adapter and one source snapshot, so
/// exact identity is both sufficient and safer than punctuation rewriting.
fn compiler_value_names_match(left: &str, right: &str) -> bool {
    let left = left.trim();
    let right = right.trim();
    !left.is_empty() && !right.is_empty() && left == right
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

/// Match rules with rulepack-compiled call-result and constructor types
/// available to receiver typing. Validation and inventory paths use this so
/// they observe the same external-library type facts as taint analysis.
pub(crate) fn match_rules_against_facts_with_factory(
    ws: &Workspace,
    rules: &[&Rule],
    factory: &Arc<RulepackTyping>,
) -> Vec<RuleMatch> {
    let mut on_file_done = || {};
    let mut on_phase_progress = |_| {};
    match_rules_against_facts_with_progress_and_mode(
        ws,
        rules,
        &mut on_file_done,
        &mut on_phase_progress,
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
    factory: &Arc<RulepackTyping>,
) -> Vec<RuleMatch> {
    match_rules_against_facts_with_factory(ws, &[rule], factory)
}

/// Match one rule's exact compiler-owned endpoint while postponing only
/// constraints that require a source-specific taint view.
///
/// Rulepack validation uses this for non-finding typing rules. A typing rule
/// can condition a receiver-state transfer on tainted input, but it can never
/// produce a security finding for the taint replay path to observe. This mode
/// still proves the call/write target, receiver type, imports, argument shape,
/// and every other structural constraint.
pub(crate) fn match_rule_endpoint_for_validation(
    ws: &Workspace,
    rule: &Rule,
    factory: &Arc<RulepackTyping>,
) -> Vec<RuleMatch> {
    let mut on_file_done = || {};
    let mut on_phase_progress = |_| {};
    match_rules_against_facts_with_progress_and_mode(
        ws,
        &[rule],
        &mut on_file_done,
        &mut on_phase_progress,
        MatchRunConfig {
            mode: ConstraintMode::TaintEndpoint,
            taint_view: None,
            scan_files: None,
            factory,
            dedup_file_matches: false,
            retention: FactRetention::Transient,
            global_headers: None,
        },
    )
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
    let factory = build_rulepack_typing(rules);
    let mut on_phase_progress = |_| {};
    match_rules_against_facts_with_progress_and_mode(
        ws,
        rules,
        &mut on_file_done,
        &mut on_phase_progress,
        MatchRunConfig {
            mode: ConstraintMode::Strict,
            taint_view: None,
            scan_files: None,
            factory: &factory,
            dedup_file_matches: false,
            retention: FactRetention::Transient,
            global_headers: None,
        },
    )
}

/// Exact staged progress for broad matcher planning and body evaluation.
///
/// A broad match is a compiler pipeline, not one flat per-file loop: cheap
/// raw anchors reject impossible files, compact syntax/import headers narrow
/// the survivors, and only then are exact adapter-lowered bodies decoded.
/// Reporting those stages separately keeps terminal progress tied to work
/// that is actually completing instead of emitting a burst of synthetic
/// "skipped file" ticks after planning has already finished.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) enum MatcherProgressStage {
    RawAnchors,
    SyntaxHeaders,
    ReceiverAncestry,
    ReceiverEvidence,
    ExactBodies,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) enum MatcherProgress {
    PhaseStarted {
        stage: MatcherProgressStage,
        total: usize,
    },
    UnitCompleted,
    PhaseFinished,
}

fn load_receiver_ancestry_with_progress<F>(
    ws: &Workspace,
    on_completed: &mut F,
) -> Arc<bonsai_index::ReceiverAncestry>
where
    F: FnMut() + ?Sized,
{
    std::thread::scope(|scope| {
        // Compiler-object workers report through a bounded channel so the UI
        // callback remains on its coordinating thread. This keeps progress
        // live without making a terminal renderer `Send` or letting display
        // work alter compiler scheduling.
        let (progress_tx, progress_rx) = std::sync::mpsc::sync_channel::<()>(64);
        let worker_tx = progress_tx.clone();
        let worker = std::thread::Builder::new()
            .name("bonsai-security-receiver-ancestry".to_string())
            .stack_size(bonsai_common::compiler_worker_stack_bytes())
            .spawn_scoped(scope, move || {
                ws.compiler_receiver_ancestry_with_progress(|| {
                    let _ = worker_tx.send(());
                })
            })
            .expect("spawn receiver-ancestry worker");
        drop(progress_tx);
        for () in progress_rx {
            on_completed();
        }
        worker.join().expect("receiver ancestry worker panicked")
    })
}

pub(crate) fn match_rules_against_facts_for_strict_with_phase_progress_on_files<F>(
    ws: &Workspace,
    rules: &[&Rule],
    files: &[FileId],
    factory: &Arc<RulepackTyping>,
    mut on_progress: F,
) -> Vec<RuleMatch>
where
    F: FnMut(MatcherProgress),
{
    let mut on_file_done = || {};
    match_rules_against_facts_with_progress_and_mode(
        ws,
        rules,
        &mut on_file_done,
        &mut on_progress,
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

pub(crate) fn match_rules_against_facts_for_inventory_with_phase_progress_on_files<F>(
    ws: &Workspace,
    rules: &[&Rule],
    files: &[FileId],
    factory: &Arc<RulepackTyping>,
    mut on_progress: F,
) -> Vec<RuleMatch>
where
    F: FnMut(MatcherProgress),
{
    let mut on_file_done = || {};
    match_rules_against_facts_with_progress_and_mode(
        ws,
        rules,
        &mut on_file_done,
        &mut on_progress,
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
    let mut on_phase_progress = |_| {};
    let factory = build_rulepack_typing(&[rule]);
    match_rules_against_facts_with_progress_and_mode(
        ws,
        &[rule],
        &mut on_file_done,
        &mut on_phase_progress,
        MatchRunConfig {
            mode: ConstraintMode::Strict,
            taint_view: Some(taint_view),
            scan_files: None,
            factory: &factory,
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
    pub factory: &'a RulepackTyping,
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
    factory: &RulepackTyping,
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
        MatchKind::Read | MatchKind::Return | MatchKind::Param | MatchKind::Missing | MatchKind::Type => None,
    }
}

fn call_rule_match_passes_constraints_at_expected_hit(
    ws: &Workspace,
    prepared: &PreparedRule<'_>,
    expected: &RuleMatch,
    taint_view: &InterTaintView<'_>,
    factory: &RulepackTyping,
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
    let compiler_imports = ws.db().compiler_import_index_uncached(file);
    let requirements = DeclFactRequirements::for_rules(std::iter::once(prepared));
    let bundle = decl_match_facts_for_retention(
        ws,
        file,
        Some(&file_index),
        DeclMatchFactsRequest {
            factory,
            requirements,
            retention: FactRetention::Transient,
            compiler_imports: compiler_imports.as_ref(),
            global_headers: Some(global_headers.as_ref()),
            call_result_type_decls: None,
        },
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
            let Some(matched_callee) = prepared.call_target_matches(call, &receiver_types, &facts.alias_map)
            else {
                continue;
            };
            if external_receiver_type_is_workspace_shadow_at(
                prepared,
                &receiver_types,
                &file_index.defs,
                compiler_imports.as_ref(),
                Some(&matched_callee),
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
            let workspace_context = WorkspaceCallIdentityContext {
                ws,
                global: global_headers.as_ref(),
                caller: decl,
            };
            if prepared_call_binding_origin_is_invalid(
                prepared,
                ws.db()
                    .adapter_for(decl.name_span.file)
                    .is_some_and(|adapter| adapter.capabilities().bare_call_constructor_syntax),
                decl,
                Some(&file_index.defs),
                Some(&workspace_context),
                call,
                &facts.alias_map,
                compiler_imports.as_ref(),
            ) {
                continue;
            }
            if prepared.rule.match_spec.kind == MatchKind::New
                && !call_has_new_identity(
                    Some(&workspace_context),
                    factory,
                    &prepared.rule.language,
                    call,
                    &facts.alias_map,
                    compiler_imports.as_ref(),
                )
            {
                continue;
            }
            let receiver_call_count =
                receiver_method_key(&call.callee).and_then(|key| facts.receiver_counts.get(&key).copied());
            if constraints_pass(ConstraintEval {
                rule_id: &prepared.rule.id,
                callee: &matched_callee,
                receiver: call.receiver.as_deref(),
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
                    string_compositions: &file_index.string_compositions,
                    factory_import_identity: Some(FactoryImportIdentityContext {
                        required_imports: &prepared.rule.imports,
                        alias_map: &facts.alias_map,
                        compiler_imports: compiler_imports.as_ref(),
                        workspace: Some((ws, global_headers.as_ref())),
                    }),
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
    let compiler_imports = transient_import_index(ws, file);
    let alias_map =
        file_alias_map_with_compiler_imports(ws, file, FactRetention::Transient, compiler_imports.as_ref());

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
            if !prepared.base_name_allows(&write.target) {
                continue;
            }
            let receiver_types =
                exact_declared_receiver_types_for_match_base(decl, &write.target, compiler_imports.as_ref());
            if !base_receiver_type_allows(prepared, Some(decl), &write.target, &receiver_types, &[])
                || external_receiver_type_is_workspace_shadow_at(
                    prepared,
                    &receiver_types,
                    &file_index.defs,
                    compiler_imports.as_ref(),
                    Some(&write.target),
                )
            {
                continue;
            }
            if !prepared.call_context_allows(
                &write.target,
                &receiver_types,
                &alias_map,
                file_packages.as_ref(),
            ) {
                continue;
            }
            if prepared_write_binding_origin_is_invalid(
                ws,
                file,
                prepared,
                decl,
                &file_index.defs,
                &write.target,
                write.span,
                &alias_map,
                compiler_imports.as_ref(),
            ) {
                continue;
            }
            let args = [write.argument.clone()];
            let ast_arg_values = [write.ast_values];
            if constraints_pass(ConstraintEval {
                rule_id: &prepared.rule.id,
                callee: &write.target,
                receiver: None,
                args: &args,
                receiver_types: &receiver_types,
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
                    string_compositions: &file_index.string_compositions,
                    factory_import_identity: None,
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
        if !prepared.base_name_allows(&r.name) {
            continue;
        }
        let Some(decl) = innermost_decl_for_span(&file_index.defs, r.span) else {
            continue;
        };
        let receiver_types =
            exact_declared_receiver_types_for_match_base(decl, &r.name, compiler_imports.as_ref());
        if !base_receiver_type_allows(prepared, Some(decl), &r.name, &receiver_types, &[])
            || external_receiver_type_is_workspace_shadow_at(
                prepared,
                &receiver_types,
                &file_index.defs,
                compiler_imports.as_ref(),
                Some(&r.name),
            )
        {
            continue;
        }
        if !prepared.call_context_allows(&r.name, &receiver_types, &alias_map, file_packages.as_ref()) {
            continue;
        }
        if prepared_write_binding_origin_is_invalid(
            ws,
            file,
            prepared,
            decl,
            &file_index.defs,
            &r.name,
            r.span,
            &alias_map,
            compiler_imports.as_ref(),
        ) {
            continue;
        }
        if constraints_pass(ConstraintEval {
            rule_id: &prepared.rule.id,
            callee: &r.name,
            receiver: None,
            args: &[],
            receiver_types: &receiver_types,
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
    let rule_typing = build_rulepack_typing(&[rule]);

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
                    global.as_ref(),
                    rule_typing.as_ref(),
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
            MatchKind::Read | MatchKind::Return | MatchKind::Param | MatchKind::Missing | MatchKind::Type => {
            }
        }
    }
    false
}

/// Matcher mode used by taint-analysis for sink endpoint discovery. The
/// semantic taint graph is authoritative for whether user-controlled
/// data reaches a sink, so sink-side constraints are ignored in this
/// mode.
pub(crate) fn match_rules_against_facts_for_taint_with_phase_progress_on_files<F>(
    ws: &Workspace,
    rules: &[&Rule],
    files: &[FileId],
    factory: &Arc<RulepackTyping>,
    mut on_progress: F,
) -> Vec<RuleMatch>
where
    F: FnMut(MatcherProgress),
{
    let mut on_file_done = || {};
    match_rules_against_facts_with_progress_and_mode(
        ws,
        rules,
        &mut on_file_done,
        &mut on_progress,
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
    factory: &Arc<RulepackTyping>,
    mut on_file_done: F,
) -> Vec<RuleMatch>
where
    F: FnMut(),
{
    let mut on_phase_progress = |_| {};
    match_rules_against_facts_with_progress_and_mode(
        ws,
        rules,
        &mut on_file_done,
        &mut on_phase_progress,
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

pub(crate) fn match_rules_against_facts_for_sink_inventory_with_phase_progress_on_files<F>(
    ws: &Workspace,
    rules: &[&Rule],
    files: &[FileId],
    factory: &Arc<RulepackTyping>,
    mut on_progress: F,
) -> Vec<RuleMatch>
where
    F: FnMut(MatcherProgress),
{
    let mut on_file_done = || {};
    match_rules_against_facts_with_progress_and_mode(
        ws,
        rules,
        &mut on_file_done,
        &mut on_progress,
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

fn parallel_map_with_progress<T, R, M, P>(items: &[T], map: M, on_completed: &mut P) -> Vec<R>
where
    T: Sync,
    R: Send,
    M: Fn(&T) -> R + Send + Sync,
    P: FnMut() + ?Sized,
{
    if items.len() <= 1 {
        return items
            .iter()
            .map(|item| {
                let result = map(item);
                on_completed();
                result
            })
            .collect();
    }

    collect_parallel_with_progress(
        items.len(),
        move |tick_tx| {
            use rayon::prelude::*;
            items
                .par_iter()
                .map(|item| {
                    let result = map(item);
                    let _ = tick_tx.send(());
                    result
                })
                .collect::<Vec<_>>()
        },
        on_completed,
    )
}

fn parallel_into_map_with_progress<T, R, M, P>(items: Vec<T>, map: M, on_completed: &mut P) -> Vec<R>
where
    T: Send,
    R: Send,
    M: Fn(T) -> R + Send + Sync,
    P: FnMut() + ?Sized,
{
    if items.len() <= 1 {
        return items
            .into_iter()
            .map(|item| {
                let result = map(item);
                on_completed();
                result
            })
            .collect();
    }

    collect_parallel_with_progress(
        items.len(),
        move |tick_tx| {
            use rayon::prelude::*;
            items
                .into_par_iter()
                .map(|item| {
                    let result = map(item);
                    let _ = tick_tx.send(());
                    result
                })
                .collect::<Vec<_>>()
        },
        on_completed,
    )
}

fn collect_parallel_with_progress<R, P, W>(item_count: usize, worker: W, on_completed: &mut P) -> Vec<R>
where
    R: Send,
    P: FnMut() + ?Sized,
    W: FnOnce(mpsc::Sender<()>) -> Vec<R> + Send,
{
    let (tick_tx, tick_rx) = mpsc::channel();
    std::thread::scope(|scope| {
        let worker = std::thread::Builder::new()
            .name("bonsai-security-progress".to_string())
            .stack_size(bonsai_common::compiler_worker_stack_bytes())
            .spawn_scoped(scope, move || worker(tick_tx))
            .expect("spawn security progress worker");
        for _ in 0..item_count {
            if tick_rx.recv().is_err() {
                break;
            }
            on_completed();
        }
        match worker.join() {
            Ok(results) => results,
            Err(panic) => std::panic::resume_unwind(panic),
        }
    })
}

fn match_rules_against_facts_with_progress_and_mode<F, P>(
    ws: &Workspace,
    rules: &[&Rule],
    on_file_done: &mut F,
    on_phase_progress: &mut P,
    config: MatchRunConfig<'_, '_>,
) -> Vec<RuleMatch>
where
    F: FnMut(),
    P: FnMut(MatcherProgress),
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
    let prepared: Vec<PreparedRule<'_>> = rules
        .iter()
        .filter_map(|rule| {
            let mut prepared = PreparedRule::new(rule)?;
            add_lifecycle_producer_anchors(&mut prepared, factory);
            Some(prepared)
        })
        .collect();
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
    if total > 0 {
        on_phase_progress(MatcherProgress::PhaseStarted {
            stage: MatcherProgressStage::RawAnchors,
            total,
        });
    }
    let raw_scan_candidates = parallel_map_with_progress(
        &files,
        |file| {
            let adapter = ws.db().adapter_for(*file)?;
            let file_rules = prepared_by_language.get(adapter.language_id().as_str())?;
            let Ok(snapshot) = ws.db().vfs().snapshot(*file) else {
                return None;
            };
            let call_text_prefilter = adapter.capabilities().call_text_prefilter;
            let anchor_matches =
                file_rules.text_anchor_matches(snapshot.text.as_ref(), call_text_prefilter, mode);
            file_rules
                .syntax_target_possible_in_text_with_matches(
                    snapshot.text.as_ref(),
                    mode,
                    call_text_prefilter,
                    &anchor_matches,
                )
                .then_some((*file, anchor_matches))
        },
        &mut || on_phase_progress(MatcherProgress::UnitCompleted),
    )
    .into_iter()
    .flatten()
    .collect::<Vec<_>>();
    let raw_scan_files = raw_scan_candidates
        .iter()
        .map(|(file, _)| *file)
        .collect::<Vec<_>>();
    if total > 0 {
        on_phase_progress(MatcherProgress::PhaseFinished);
    }
    // Retrieval/path-filtered workspaces intentionally begin without a
    // whole-workspace store attached. Their candidates retain stable full
    // workspace FileIds, so bind the existing immutable generation to this
    // exact raw-anchor worklist before import/syntax planning. This method is
    // read-only and strong-digest validates every selected source; on a miss
    // the ordinary adapter-owned Tree-sitter fallback remains exact.
    let compiler_store_started = debug_security_phase.then(Instant::now);
    let compiler_store_reused = db
        .attach_reusable_compiler_object_store_for_files(&raw_scan_files)
        .unwrap_or_else(|error| {
            bonsai_diagnostics::debug_log!(
                "compiler-object",
                "scoped compiler-object generation unavailable for security planning: {error}"
            );
            false
        });
    if let Some(started) = compiler_store_started {
        bonsai_diagnostics::debug_log!(
            "security-phase",
            "matcher compiler-object attachment: {:.3}s files={} reused={}",
            started.elapsed().as_secs_f64(),
            raw_scan_files.len(),
            compiler_store_reused
        );
    }
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
    let mut receiver_ancestry: Option<Arc<bonsai_index::ReceiverAncestry>> = None;
    if let Some(started) = headers_started {
        bonsai_diagnostics::debug_log!(
            "security-phase",
            "matcher symbol projection: {:.3}s declarations={} receiver_types={}",
            started.elapsed().as_secs_f64(),
            global_file_indexes.as_ref().map_or(0, |headers| headers.len()),
            receiver_ancestry.as_ref().map_or(0, |ancestry| ancestry.len())
        );
    }
    let receiver_base_map = global_file_indexes
        .as_ref()
        .map_or_else(AHashMap::new, |headers| {
            workspace_receiver_base_map_if_needed(&prepared, mode, headers.as_ref())
        });
    // Apply exact import/package and syntax-header constraints to raw-anchor
    // survivors. Retain only rule references for the body phase below. This
    // is the compiler's header/body boundary: scheduling changes, but every
    // rule and file keeps the same semantics.
    let package_filter_started = debug_security_phase.then(Instant::now);
    let text_filter_ns = AtomicU64::new(0);
    let syntax_load_ns = AtomicU64::new(0);
    let syntax_filter_ns = AtomicU64::new(0);
    let build_scan_plan = |candidate_files: &[(FileId, BatchTextAnchorMatches)],
                           receiver_base_map: &AHashMap<String, Vec<String>>,
                           receiver_ancestry: Option<&Arc<bonsai_index::ReceiverAncestry>>,
                           receiver_ancestry_complete: bool,
                           on_completed: &mut dyn FnMut()| {
        parallel_map_with_progress(
            candidate_files,
            |candidate| {
                let file = candidate.0;
                let matched_text_anchors = &candidate.1;
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
                let text_filter_started = debug_security_phase.then(Instant::now);
                let rules = file_rules.filtered_rule_refs_for_text(FileRuleFilterContext {
                    ws,
                    file,
                    text: snapshot.text.as_ref(),
                    mode,
                    retention,
                    prewarmed_import_contexts: import_contexts,
                    compiler_imports,
                    matched_text_anchors: Some(matched_text_anchors),
                });
                if let Some(started) = text_filter_started {
                    record_elapsed_ns(&text_filter_ns, started);
                }
                // Import/package filtering is monotone: the syntax header can
                // only reject more rules, never restore one. Do not hash,
                // decompress, decode, and integrity-check a compiler syntax
                // payload when no rule survived the cheaper exact header.
                if rules.is_empty() {
                    return Some((file, rules, None, false));
                }
                let syntax_load_started = debug_security_phase.then(Instant::now);
                let Some(mut syntax) = ws.db().compiler_syntax_header_uncached(file) else {
                    return Some((file, rules, None, false));
                };
                if let Some(started) = syntax_load_started {
                    record_elapsed_ns(&syntax_load_ns, started);
                }
                if let Some(ancestry) = receiver_ancestry.as_ref() {
                    ancestry.apply_to_syntax_header(&mut syntax);
                }
                if receiver_ancestry.is_none() {
                    enrich_compiler_syntax_header_receiver_types(&mut syntax, receiver_base_map);
                }
                let syntax_filter_started = debug_security_phase.then(Instant::now);
                let (filtered_rules, deferred, needs_workspace_constructor_resolution) = file_rules
                    .filtered_rule_refs_for_syntax_header(
                        rules.clone(),
                        &syntax,
                        snapshot.text.as_ref(),
                        compiler_imports,
                        language.as_str(),
                        receiver_ancestry_complete,
                    );
                if let Some(started) = syntax_filter_started {
                    record_elapsed_ns(&syntax_filter_ns, started);
                }
                let deferred_plan = deferred.then(|| {
                    (
                        rules,
                        syntax,
                        Arc::clone(&snapshot.text),
                        compiler_imports.cloned(),
                        language.as_str().to_string(),
                    )
                });
                Some((
                    file,
                    filtered_rules,
                    deferred_plan,
                    needs_workspace_constructor_resolution,
                ))
            },
            on_completed,
        )
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
    };
    let ancestry_already_complete =
        !needs_receiver_ancestry || global_file_indexes.is_some() || receiver_ancestry.is_some();
    if !raw_scan_files.is_empty() {
        on_phase_progress(MatcherProgress::PhaseStarted {
            stage: MatcherProgressStage::SyntaxHeaders,
            total: raw_scan_files.len(),
        });
    }
    let initial_plan = build_scan_plan(
        &raw_scan_candidates,
        &receiver_base_map,
        receiver_ancestry.as_ref(),
        ancestry_already_complete,
        &mut || on_phase_progress(MatcherProgress::UnitCompleted),
    );
    if !raw_scan_files.is_empty() {
        on_phase_progress(MatcherProgress::PhaseFinished);
    }
    let mut deferred_plans = Vec::new();
    let mut scan_plan = Vec::new();
    let mut needs_workspace_call_resolution = false;
    for (file, rules, deferred, needs_call_resolution) in initial_plan {
        if let Some(deferred) = deferred {
            deferred_plans.push((file, deferred));
        } else if !rules.is_empty() {
            needs_workspace_call_resolution |= needs_call_resolution;
            scan_plan.push((file, rules));
        }
    }
    let needs_workspace_parameter_identity = scan_plan.iter().any(|(_, rules)| {
        rules
            .iter()
            .any(|prepared| prepared_rule_needs_external_parameter_identity(prepared))
    });
    if !deferred_plans.is_empty() {
        let deferred_file_count = deferred_plans.len();
        on_phase_progress(MatcherProgress::PhaseStarted {
            stage: MatcherProgressStage::ReceiverAncestry,
            total: ws.db().vfs().all_files().len(),
        });
        let ancestry_started = debug_security_phase.then(Instant::now);
        if receiver_ancestry.is_none() && global_file_indexes.is_none() {
            receiver_ancestry = Some(load_receiver_ancestry_with_progress(ws, &mut || {
                on_phase_progress(MatcherProgress::UnitCompleted);
            }));
        }
        on_phase_progress(MatcherProgress::PhaseFinished);
        on_phase_progress(MatcherProgress::PhaseStarted {
            stage: MatcherProgressStage::ReceiverEvidence,
            total: deferred_file_count,
        });
        let completed_deferred = parallel_into_map_with_progress(
            deferred_plans,
            |(file, (rules, mut syntax, source_text, compiler_imports, language))| {
                if let Some(ancestry) = receiver_ancestry.as_ref() {
                    ancestry.apply_to_syntax_header(&mut syntax);
                } else {
                    enrich_compiler_syntax_header_receiver_types(&mut syntax, &receiver_base_map);
                }
                let file_rules = prepared_by_language.get(&language)?;
                let (rules, _, needs_call_resolution) = file_rules.filtered_rule_refs_for_syntax_header(
                    rules,
                    &syntax,
                    source_text.as_ref(),
                    compiler_imports.as_ref(),
                    &language,
                    true,
                );
                (!rules.is_empty()).then_some((file, rules, needs_call_resolution))
            },
            &mut || on_phase_progress(MatcherProgress::UnitCompleted),
        )
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
        on_phase_progress(MatcherProgress::PhaseFinished);
        for (file, rules, needs_call_resolution) in completed_deferred {
            needs_workspace_call_resolution |= needs_call_resolution;
            scan_plan.push((file, rules));
        }
        scan_plan.sort_unstable_by_key(|(file, _)| file.raw());
        if let Some(started) = ancestry_started {
            bonsai_diagnostics::debug_log!(
                "security-phase",
                "matcher deferred receiver ancestry: {:.3}s files={} declarations={} receiver_types={}",
                started.elapsed().as_secs_f64(),
                deferred_file_count,
                global_file_indexes.as_ref().map_or(0, |headers| headers.len()),
                receiver_ancestry.as_ref().map_or(0, |ancestry| ancestry.len())
            );
        }
    }
    if (needs_workspace_call_resolution || needs_workspace_parameter_identity)
        && global_file_indexes.is_none()
    {
        // Compact headers proved that at least one surviving typed call can
        // change its verdict through exact first-party call identity, or that
        // an exact typed parameter needs a workspace-shadow check before it
        // can stand in for a missing external import. Load only
        // declaration/type headers before the parallel body phase so imported
        // module values, declared returns, constructors, and lexical shadowing
        // are resolved by compiler facts. No bodies or IDG are materialized by
        // this step.
        global_file_indexes = Some(matcher_global_headers(ws, retention));
    }
    if let Some(started) = package_filter_started {
        bonsai_diagnostics::debug_log!(
            "security-phase",
            "matcher header/package filter: {:.3}s raw_candidates={} body_candidates={} worker_cpu(text={:.3}s syntax_load={:.3}s syntax_filter={:.3}s)",
            started.elapsed().as_secs_f64(),
            raw_scan_files.len(),
            scan_plan.len(),
            text_filter_ns.load(Ordering::Relaxed) as f64 / 1_000_000_000.0,
            syntax_load_ns.load(Ordering::Relaxed) as f64 / 1_000_000_000.0,
            syntax_filter_ns.load(Ordering::Relaxed) as f64 / 1_000_000_000.0,
        );
        let mut retained_by_rule = AHashMap::<&str, usize>::new();
        for (_, rules) in &scan_plan {
            for rule in rules {
                *retained_by_rule.entry(rule.rule.id.as_str()).or_default() += 1;
            }
        }
        let mut retained_by_rule = retained_by_rule.into_iter().collect::<Vec<_>>();
        retained_by_rule
            .sort_unstable_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(right.0)));
        let summary_count = retained_by_rule.len().min(20);
        let summary = retained_by_rule[..summary_count]
            .iter()
            .map(|(rule, count)| format!("{rule}:{count}"))
            .collect::<Vec<_>>()
            .join(",");
        bonsai_diagnostics::debug_log!("security-phase", "matcher most-retained rules: {summary}");
    }
    // Submit smaller exact bodies first so a few large files cannot occupy
    // every work-stealing thread while waiting for weighted memory permits.
    // Downstream match ordering is canonicalized before emission.
    scan_plan.sort_by_cached_key(|(file, _)| {
        ws.db()
            .vfs()
            .snapshot(*file)
            .map_or(0, |snapshot| snapshot.text.len())
    });
    let compiler_session_started = debug_security_phase.then(Instant::now);
    let body_files = scan_plan.iter().map(|(file, _)| *file).collect::<Vec<_>>();
    let has_body_work = !scan_plan.is_empty();
    if has_body_work {
        on_phase_progress(MatcherProgress::PhaseStarted {
            stage: MatcherProgressStage::ExactBodies,
            total: scan_plan.len(),
        });
    }
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
    // Each `scan_file_rules` writes only to its own per-file Vec. One
    // continuous work-stealing pool submits the complete exact worklist;
    // source-weighted permits bound the actual units concurrently resident.
    // This lets small files use every CPU without allowing a few large files
    // to overcommit memory or introducing batch barriers. Match collection
    // order is non-deterministic across runs, but downstream callers sort
    // before emission to keep finding ids stable.
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
    let parallel_width = workers.min(scan_plan.len()).max(1);
    let memory_permits = bonsai_common::SyntaxMemoryPermitPool::for_streaming_compiler_bodies();
    let phase_timings = debug_security_phase.then(MatcherPhaseTimings::default);
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
        let compiler_object_started = debug_security_phase.then(Instant::now);
        let Some(compiler_object) = ws.db().compiler_file_object_uncached(file) else {
            return (file_out, false);
        };
        if let (Some(started), Some(timings)) = (compiler_object_started, phase_timings.as_ref()) {
            record_elapsed_ns(&timings.compiler_object, started);
        }
        let file_imports = compiler_object.imports;
        let Some(file_index) = compiler_object.declarations else {
            return (file_out, true);
        };
        let remap_started = debug_security_phase.then(Instant::now);
        let mut file_index = match global_file_indexes.as_ref() {
            Some(headers) => ws.db().remap_decl_index_to_headers(headers.as_ref(), file_index),
            None => file_index,
        };
        if let Some(ancestry) = receiver_ancestry.as_ref() {
            ancestry.apply_to_decl_index(&mut file_index);
        }
        if let (Some(started), Some(timings)) = (remap_started, phase_timings.as_ref()) {
            record_elapsed_ns(&timings.remap, started);
        }
        // Reuse the same exact compiler/package evidence representation for
        // every endpoint family in this body. Component and manifest sets are
        // shared by reference; only file-local imports are projected here.
        // This avoids rebuilding marker-expanded package hash sets in calls,
        // reads, writes, and params without changing any matcher verdict.
        let package_evidence = file_package_planning_evidence(
            ws,
            file,
            file_rules.include_workspace_package_context,
            retention,
            prewarmed_import_contexts.get(language.as_str()),
            file_imports.as_ref(),
        );
        let ctx = FileScanContext {
            ws,
            file,
            file_index: &file_index,
            file_imports: file_imports.as_ref(),
            package_evidence: &package_evidence,
            mode,
            taint_view,
            retention,
            receiver_base_map: &receiver_base_map,
            global_headers: global_file_indexes.as_deref(),
            debug_timings: phase_timings.as_ref(),
        };
        let body_scan_started = debug_security_phase.then(Instant::now);
        scan_file_rules(&ctx, &file_rules, &mut file_out);
        if let (Some(started), Some(timings)) = (body_scan_started, phase_timings.as_ref()) {
            record_elapsed_ns(&timings.body_scan, started);
        }
        if dedup_file_matches {
            dedup_inventory_matches(&mut file_out);
        }
        (file_out, true)
    };
    if parallel_width <= 1 || scan_plan.len() <= 1 {
        let results = scan_plan
            .iter()
            .flat_map(|(file, rule_refs)| {
                let (file_out, _) = scan_planned_file(*file, rule_refs);
                on_file_done();
                on_phase_progress(MatcherProgress::UnitCompleted);
                file_out
            })
            .collect();
        if has_body_work {
            on_phase_progress(MatcherProgress::PhaseFinished);
        }
        return results;
    }
    let run_parallel_scan = |pool: Option<&rayon::ThreadPool>| {
        let scan_total = scan_plan.len();
        let (tick_tx, tick_rx) = mpsc::channel();
        let parsed_files = Arc::new(AtomicUsize::new(0));
        let text_skipped_files = Arc::new(AtomicUsize::new(target_prefilter_skipped));
        let parsed_files_worker = parsed_files.clone();
        std::thread::scope(|scope| {
            let worker = std::thread::Builder::new()
                .name("bonsai-security-match-coordinator".to_string())
                .stack_size(bonsai_common::compiler_worker_stack_bytes())
                .spawn_scoped(scope, move || {
                    let scan = || {
                        use rayon::prelude::*;
                        scan_plan
                            .par_iter()
                            .zip(source_bytes.par_iter())
                            .flat_map_iter(|((file, rule_refs), source_bytes)| {
                                let _memory_permit = memory_permits.acquire(*source_bytes);
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
                })
                .expect("spawn security match coordinator");
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
                        on_phase_progress(MatcherProgress::UnitCompleted);
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
                        if let Some(timings) = phase_timings.as_ref() {
                            let seconds = |counter: &AtomicU64| {
                                counter.load(Ordering::Relaxed) as f64 / 1_000_000_000.0
                            };
                            bonsai_diagnostics::debug_log!(
                                "security-phase",
                                "matcher aggregate worker CPU: compiler_object={:.3}s remap={:.3}s body_scan={:.3}s call_setup={:.3}s decl_facts={:.3}s call_match={:.3}s refs={:.3}s flow_reads={:.3}s writes={:.3}s params={:.3}s types={:.3}s returns={:.3}s missing={:.3}s direct_receiver_files={} derived_receiver_files={} derived_receiver_decls={}",
                                seconds(&timings.compiler_object),
                                seconds(&timings.remap),
                                seconds(&timings.body_scan),
                                seconds(&timings.call_setup),
                                seconds(&timings.decl_facts),
                                seconds(&timings.call_match),
                                seconds(&timings.refs_scan),
                                seconds(&timings.flow_reads_scan),
                                seconds(&timings.writes_scan),
                                seconds(&timings.params_scan),
                                seconds(&timings.types_scan),
                                seconds(&timings.returns_scan),
                                seconds(&timings.missing_scan),
                                timings.direct_receiver_files.load(Ordering::Relaxed),
                                timings.derived_receiver_files.load(Ordering::Relaxed),
                                timings.derived_receiver_decls.load(Ordering::Relaxed),
                            );
                        }
                    }
                    out
                }
                Err(panic) => std::panic::resume_unwind(panic),
            }
        })
    };
    let results = match rayon::ThreadPoolBuilder::new()
        .num_threads(parallel_width)
        .stack_size(matcher_worker_stack_bytes())
        .build()
    {
        Ok(pool) => run_parallel_scan(Some(&pool)),
        Err(_) => run_parallel_scan(None),
    };
    if has_body_work {
        on_phase_progress(MatcherProgress::PhaseFinished);
    }
    results
}

fn matcher_worker_count() -> usize {
    let available = std::thread::available_parallelism()
        .map(std::num::NonZeroUsize::get)
        .unwrap_or(1)
        .max(1);
    // Source-size-weighted permits apply the live memory budget after rule
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

/// Keep one inventory row per exact compiler binding and rule, preferring
/// callable attribution and the narrowest syntax span over duplicate wrapper
/// projections.
pub(crate) fn dedup_inventory_matches(matches: &mut Vec<RuleMatch>) {
    // Two compiler views can anchor one place at the same token start while
    // retaining different ends: the reference inventory owns the exact place,
    // while expression-flow lowering may own a surrounding value wrapper.
    // Start + bound text is the concrete binding identity; distinct same-line
    // parameters remain separate because their match text and token starts
    // differ. Keeping `span.end` in this key would emit the same source twice.
    type InventoryDedupKey = (String, String, u64, String, String);

    let mut seen: AHashMap<InventoryDedupKey, usize> = AHashMap::new();
    let mut deduped: Vec<RuleMatch> = Vec::with_capacity(matches.len());
    for m in matches.drain(..) {
        let key = (
            m.language.clone(),
            m.file.clone(),
            m.span.start,
            m.rule_id.clone(),
            m.match_text.clone(),
        );
        if let Some(&idx) = seen.get(&key) {
            // A module body and its nested callable can both expose the same
            // compiler fact. The span plus bound text is one exact endpoint;
            // `kind: param` rules intentionally use the declaration anchor,
            // so distinct parameter bindings on that declaration must not be
            // collapsed. Retain callable attribution when available.
            let existing_is_callable = deduped[idx]
                .enclosing_fn
                .as_deref()
                .is_some_and(|name| name != "__module__");
            let candidate_is_callable = m.enclosing_fn.as_deref().is_some_and(|name| name != "__module__");
            let candidate_is_narrower = m.span.len() < deduped[idx].span.len();
            if (candidate_is_callable && !existing_is_callable)
                || (candidate_is_callable == existing_is_callable && candidate_is_narrower)
            {
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
        .unwrap_or_else(bonsai_common::compiler_worker_stack_bytes)
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
    package_evidence: &'a FilePackagePlanningEvidence,
    mode: ConstraintMode,
    taint_view: Option<&'a InterTaintView<'taint>>,
    retention: FactRetention,
    receiver_base_map: &'a AHashMap<String, Vec<String>>,
    /// Present only when an ambiguous bare constructor/factory call survived
    /// compact-header planning. Exact workspace identity is then required by
    /// the body matcher before external rulepack typing can apply.
    global_headers: Option<&'a GlobalIndex>,
    debug_timings: Option<&'a MatcherPhaseTimings>,
}

#[derive(Default)]
struct MatcherPhaseTimings {
    compiler_object: AtomicU64,
    remap: AtomicU64,
    body_scan: AtomicU64,
    call_setup: AtomicU64,
    decl_facts: AtomicU64,
    call_match: AtomicU64,
    refs_scan: AtomicU64,
    flow_reads_scan: AtomicU64,
    writes_scan: AtomicU64,
    params_scan: AtomicU64,
    types_scan: AtomicU64,
    returns_scan: AtomicU64,
    missing_scan: AtomicU64,
    direct_receiver_files: AtomicUsize,
    derived_receiver_files: AtomicUsize,
    derived_receiver_decls: AtomicUsize,
}

fn record_elapsed_ns(counter: &AtomicU64, started: Instant) {
    counter.fetch_add(
        u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX),
        Ordering::Relaxed,
    );
}

struct MatchRunConfig<'a, 'taint> {
    mode: ConstraintMode,
    taint_view: Option<&'a InterTaintView<'taint>>,
    scan_files: Option<&'a [FileId]>,
    factory: &'a Arc<RulepackTyping>,
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
    receiver: Option<String>,
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
    rule.attribute.as_ref().is_some_and(|attr| attr.len() >= 2)
        || rule
            .rule
            .match_spec
            .target
            .as_ref()
            .is_some_and(|target| !target.in_class.is_empty() || !target.in_class_suffix.is_empty())
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
    call_kind_in: &'a [CallKind],
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
            MatchKind::Read | MatchKind::Write | MatchKind::Return | MatchKind::Param | MatchKind::Type => {
                rule.match_spec.target.as_ref()
            }
        };
        let target = match target {
            Some(target) => target,
            None if rule.match_spec.kind == MatchKind::Return => empty_rule_target(),
            None => return None,
        };
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
        package_signals.sort_unstable();
        package_signals.dedup();
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
            call_kind_in: target.call_kind_in.as_slice(),
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

    fn call_kind_allows(&self, call_kind: CallKind) -> bool {
        self.call_kind_in.is_empty() || self.call_kind_in.contains(&call_kind)
    }

    fn call_target_matches(
        &self,
        call: &CallFact,
        receiver_types: &[String],
        alias_map: &std::collections::HashMap<String, AliasTarget>,
    ) -> Option<String> {
        if !self.call_kind_allows(call.call_kind) {
            return None;
        }
        if self.name.is_none() && self.attribute.is_none() && self.regex.is_none() {
            return Some(call.callee.clone());
        }
        callee_or_alias_matches(
            &call.callee,
            receiver_types,
            self.name,
            self.attribute,
            self.regex.as_ref(),
            alias_map,
        )
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

    #[cfg(test)]
    fn text_possible_in_mode(
        &self,
        text: &str,
        file_packages: Option<&AHashSet<String>>,
        mode: ConstraintMode,
        call_text_prefilter: CallTextPrefilter,
    ) -> bool {
        self.text_possible_in_mode_with_anchor_lookup(
            text,
            file_packages,
            mode,
            call_text_prefilter,
            &|anchor| text.contains(anchor),
            &|anchor| call_text_anchor_possible_in(text, anchor, call_text_prefilter),
        )
    }

    #[cfg(test)]
    fn text_possible_in_mode_with_anchor_lookup(
        &self,
        text: &str,
        file_packages: Option<&AHashSet<String>>,
        mode: ConstraintMode,
        call_text_prefilter: CallTextPrefilter,
        anchor_present: &impl Fn(&str) -> bool,
        call_anchor_present: &impl Fn(&str) -> bool,
    ) -> bool {
        if !self.syntax_target_possible_in_mode_with_anchor_lookup(
            text,
            mode,
            call_text_prefilter,
            anchor_present,
            call_anchor_present,
        ) {
            return false;
        }
        self.package_text_anchors.is_empty()
            || self
                .package_text_anchors
                .iter()
                .any(|anchor| anchor_present(anchor))
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
    #[cfg(test)]
    fn syntax_target_possible_in_mode(
        &self,
        text: &str,
        mode: ConstraintMode,
        call_text_prefilter: CallTextPrefilter,
    ) -> bool {
        self.syntax_target_possible_in_mode_with_anchor_lookup(
            text,
            mode,
            call_text_prefilter,
            &|anchor| text.contains(anchor),
            &|anchor| call_text_anchor_possible_in(text, anchor, call_text_prefilter),
        )
    }

    fn syntax_target_possible_in_mode_with_anchor_lookup(
        &self,
        _text: &str,
        mode: ConstraintMode,
        call_text_prefilter: CallTextPrefilter,
        anchor_present: &impl Fn(&str) -> bool,
        call_anchor_present: &impl Fn(&str) -> bool,
    ) -> bool {
        let target_possible = self
            .text_anchor_groups
            .iter()
            .all(|group| group.is_empty() || group.iter().any(|anchor| anchor_present(anchor)));
        if !target_possible {
            return false;
        }
        if matches!(mode, ConstraintMode::Inventory) && call_text_prefilter != CallTextPrefilter::Disabled {
            if let Some(anchor) = self.call_text_anchor.as_deref() {
                if !call_anchor_present(anchor) {
                    return false;
                }
            }
        }
        true
    }

    #[cfg(test)]
    fn package_evidence_allows_text_anchor_skip(&self, file_packages: &AHashSet<String>) -> bool {
        self.package_signals.iter().any(|signal| {
            file_packages.contains(*signal)
                || (self.manifest_package_evidence_allowed()
                    && file_packages.contains(&manifest_package_marker(signal)))
                || (self.template_manifest_package_evidence_allowed()
                    && file_packages.contains(&template_manifest_package_marker(signal)))
                || (self.component_level_package_evidence_allowed()
                    && file_packages.contains(&component_import_package_marker(signal)))
                || file_packages_have_local_import_package(file_packages, signal)
        })
    }

    /// Evaluate the raw/import planning gate without materializing common
    /// workspace, component, and manifest packages into a fresh string set
    /// for every source file. The four evidence classes below are exactly the
    /// marker classes consumed by `package_evidence_allows_text_anchor_skip`;
    /// only their representation changes. Full endpoint matching continues
    /// to use the canonical materialized package set.
    fn package_evidence_allows_text_anchor_skip_in_planning(
        &self,
        evidence: &FilePackagePlanningEvidence,
    ) -> bool {
        self.package_signals.iter().any(|signal| {
            evidence.direct_file_packages.contains(*signal)
                || (evidence.manifest_packages.as_ref().is_some_and(|packages| {
                    packages.packages.contains(*signal)
                        && if evidence.is_template {
                            self.template_manifest_package_evidence_allowed()
                        } else {
                            self.manifest_package_evidence_allowed()
                        }
                }))
                || (self.component_level_package_evidence_allowed()
                    && evidence.component_packages.packages.contains(*signal))
                || file_packages_have_local_import_package(&evidence.direct_file_packages, signal)
        })
    }

    fn has_same_package_evidence_query(&self, other: &Self) -> bool {
        self.package_signals == other.package_signals
            && self.file_level_package_evidence_allowed() == other.file_level_package_evidence_allowed()
            && self.manifest_package_evidence_allowed() == other.manifest_package_evidence_allowed()
            && self.template_manifest_package_evidence_allowed()
                == other.template_manifest_package_evidence_allowed()
            && self.component_level_package_evidence_allowed()
                == other.component_level_package_evidence_allowed()
            && self.rule.package_matching == other.rule.package_matching
    }

    fn call_context_allows<P: PackageEvidence + ?Sized>(
        &self,
        callee: &str,
        receiver_types: &[String],
        alias_map: &std::collections::HashMap<String, AliasTarget>,
        file_packages: &P,
    ) -> bool {
        self.call_context_allows_impl(callee, receiver_types, alias_map, file_packages, false)
    }

    /// A source rule's exact compiler-owned enclosing class/base is itself
    /// provider provenance. This is deliberately narrower than a naming
    /// convention: the ordinary declaration-context matcher must already
    /// have proven the rule-authored `in_class` or `in_owner_base` constraint
    /// against the adapter declaration and its expanded ancestry. Package
    /// evidence remains mandatory for unconstrained names, suffix-only class
    /// conventions, and every wrong/no-owner context.
    fn source_declaration_provider_context_allows(
        &self,
        file_index: &DeclIndex,
        decl: Option<&Decl>,
    ) -> bool {
        if self.rule.kind != crate::rule::RuleKind::Source || !self.requires_call_package_signal {
            return false;
        }
        let target = match self.rule.match_spec.kind {
            MatchKind::Call | MatchKind::New | MatchKind::Missing => self.rule.match_spec.callee.as_ref(),
            MatchKind::Read | MatchKind::Write | MatchKind::Return | MatchKind::Param | MatchKind::Type => {
                self.rule.match_spec.target.as_ref()
            }
        };
        let Some(target) = target else {
            return false;
        };
        if target.in_class.is_empty() && target.in_owner_base.is_empty() {
            return false;
        }
        decl_target_context_allows(file_index, decl, Some(target), None)
    }

    fn call_or_source_context_allows<P: PackageEvidence + ?Sized>(
        &self,
        callee: &str,
        receiver_types: &[String],
        alias_map: &std::collections::HashMap<String, AliasTarget>,
        file_packages: &P,
        file_index: &DeclIndex,
        decl: Option<&Decl>,
    ) -> bool {
        self.call_context_allows(callee, receiver_types, alias_map, file_packages)
            || self.source_declaration_provider_context_allows(file_index, decl)
    }

    fn imported_default_call_context_allows<P: PackageEvidence + ?Sized>(
        &self,
        callee: &str,
        alias_map: &std::collections::HashMap<String, AliasTarget>,
        file_packages: &P,
    ) -> bool {
        self.call_context_allows_impl(callee, &[], alias_map, file_packages, true)
    }

    fn call_context_allows_impl<P: PackageEvidence + ?Sized>(
        &self,
        callee: &str,
        receiver_types: &[String],
        alias_map: &std::collections::HashMap<String, AliasTarget>,
        file_packages: &P,
        exact_binding_only: bool,
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
        let file_level_package_evidence_allowed =
            !exact_binding_only && self.file_level_package_evidence_allowed();
        let component_level_package_evidence_allowed =
            !exact_binding_only && self.component_level_package_evidence_allowed();
        let manifest_package_evidence_allowed =
            !exact_binding_only && self.manifest_package_evidence_allowed();
        let template_manifest_package_evidence_allowed =
            !exact_binding_only && self.template_manifest_package_evidence_allowed();
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
                || (manifest_package_evidence_allowed
                    && package_set_contains_import(
                        file_packages,
                        signal,
                        Some(MANIFEST_PACKAGE_PREFIX),
                        &self.rule.package_matching,
                    ))
                || (template_manifest_package_evidence_allowed
                    && package_set_contains_import(
                        file_packages,
                        signal,
                        Some(TEMPLATE_MANIFEST_PACKAGE_PREFIX),
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
            crate::rule::RuleKind::Source => self
                .rule
                .analysis_semantics
                .as_ref()
                .and_then(|semantics| semantics.allow_file_package_evidence)
                .unwrap_or(true),
            crate::rule::RuleKind::Sanitizer => false,
            // Typing rules never participate in the finding/gate path —
            // they feed factory-return resolution via build_rulepack_typing.
            crate::rule::RuleKind::Typing => false,
            crate::rule::RuleKind::Sink => {
                if allows_file_package_evidence(self.rule) {
                    return true;
                }
                let target = match self.rule.match_spec.kind {
                    MatchKind::Call | MatchKind::New | MatchKind::Missing => {
                        self.rule.match_spec.callee.as_ref()
                    }
                    MatchKind::Read
                    | MatchKind::Write
                    | MatchKind::Return
                    | MatchKind::Param
                    | MatchKind::Type => self.rule.match_spec.target.as_ref(),
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

    fn manifest_package_evidence_allowed(&self) -> bool {
        let target = match self.rule.match_spec.kind {
            MatchKind::Call | MatchKind::New | MatchKind::Missing => self.rule.match_spec.callee.as_ref(),
            MatchKind::Read | MatchKind::Write | MatchKind::Return | MatchKind::Param | MatchKind::Type => {
                self.rule.match_spec.target.as_ref()
            }
        };
        let target_has_exact_owner = target.is_some_and(|target| {
            !target.in_class.is_empty()
                || !target.in_class_suffix.is_empty()
                || !target.in_owner_base.is_empty()
                || !target.param_type_exact_in.is_empty()
                || !target.signature_param_types.is_empty()
                || !target.signature_param_annotations.is_empty()
                || !target.receiver_type_in.is_empty()
                || target
                    .regex
                    .as_deref()
                    .is_some_and(regex_has_literal_qualified_prefix)
                || (target.regex.is_none()
                    && target
                        .attribute
                        .as_ref()
                        .is_some_and(|attribute| attribute.len() >= 2))
        });
        let has_receiver_type_constraint = self
            .rule
            .constraints
            .iter()
            .any(|constraint| matches!(constraint, ConstraintKind::ReceiverTypeIn { .. }));
        match self.rule.kind {
            // A dependency manifest proves installation, not that a generic
            // local `read`, `params`, or callback parameter belongs to the
            // framework. Require compiler ownership/type evidence or an exact
            // rulepack-qualified API path before manifest evidence can
            // satisfy a source gate.
            crate::rule::RuleKind::Source => target_has_exact_owner || has_receiver_type_constraint,
            // Explicit source-independent/file-evidence sink semantics are a
            // reviewed rulepack opt-in. Ordinary taint sinks still need an
            // exact owner/type shape before a workspace manifest can replace
            // an in-file import.
            crate::rule::RuleKind::Sink => {
                allows_file_package_evidence(self.rule)
                    || target_has_exact_owner
                    || has_receiver_type_constraint
            }
            crate::rule::RuleKind::Sanitizer | crate::rule::RuleKind::Typing => false,
        }
    }

    fn component_level_package_evidence_allowed(&self) -> bool {
        let target = match self.rule.match_spec.kind {
            MatchKind::Read | MatchKind::Write | MatchKind::Return | MatchKind::Param | MatchKind::Type => {
                self.rule.match_spec.target.as_ref()
            }
            MatchKind::Call | MatchKind::New | MatchKind::Missing => self.rule.match_spec.callee.as_ref(),
        };
        let exact_structured_owner = target.is_some_and(|target| {
            target.regex.is_none()
                && target.name.is_none()
                && target
                    .attribute
                    .as_ref()
                    .is_some_and(|attribute| attribute.len() >= 2)
        });
        let constrained_receiver = target.is_some_and(|target| {
            !target.base_name_in.is_empty()
                || !target.receiver_type_in.is_empty()
                || !target.in_class.is_empty()
                || !target.in_class_suffix.is_empty()
                || !target.in_owner_base.is_empty()
                || !target.param_type_exact_in.is_empty()
                || !target.signature_param_types.is_empty()
                || !target.signature_param_annotations.is_empty()
        }) || self
            .rule
            .constraints
            .iter()
            .any(|constraint| matches!(constraint, ConstraintKind::ReceiverTypeIn { .. }));

        match self.rule.kind {
            // A connected importer proves which framework owns a split-out
            // route module, but source evidence still needs both an explicit
            // framework declaration and an exact compiler-owned target.
            // Regex/name-only source shapes remain file-local.
            crate::rule::RuleKind::Source => {
                !self.rule.frameworks.is_empty() && (exact_structured_owner || constrained_receiver)
            }
            // A package imported by the same compiler-resolved component is
            // valid supporting evidence for an exact receiver/member sink.
            // This is what lets a service module consume a DB handle created
            // by its imported connection module. Bare calls such as
            // `serialize(...)` remain ineligible, so an unrelated package
            // import elsewhere in the component cannot authorize them.
            crate::rule::RuleKind::Sink => exact_structured_owner || constrained_receiver,
            crate::rule::RuleKind::Sanitizer | crate::rule::RuleKind::Typing => false,
        }
    }

    fn template_manifest_package_evidence_allowed(&self) -> bool {
        // Template adapters lower helper calls in a runtime-owned rendering
        // context where the template itself cannot carry a normal language
        // import. The file extension and package manifest provide that
        // context; ordinary source files never receive this marker.
        self.rule.kind == crate::rule::RuleKind::Sink && self.file_level_package_evidence_allowed()
    }

    fn needs_workspace_package_context(&self) -> bool {
        self.requires_call_package_signal
            // Language-scoped dependency manifests are represented as plain
            // package evidence and intentionally use the same admission rule
            // as an exact import in this file. Workspace/component *import*
            // evidence carries a distinct marker and remains subject to the
            // narrower source/sink policies below. Without the file-level
            // arm, compiler-proven runtime globals and inherited framework
            // APIs can be proven installed by dependency inventory but can
            // never satisfy their source rule's package gate.
            && (self.file_level_package_evidence_allowed()
                || self.manifest_package_evidence_allowed()
                || self.template_manifest_package_evidence_allowed()
                || self.component_level_package_evidence_allowed()
            )
    }
}

fn empty_rule_target() -> &'static RuleTarget {
    static EMPTY: std::sync::OnceLock<RuleTarget> = std::sync::OnceLock::new();
    EMPTY.get_or_init(RuleTarget::default)
}

/// A `requires_state` constraint can only hold when the state's producing
/// call (a rulepack lifecycle transition, e.g. `cancel` → `cancelled`) is in
/// the same file as the matched call: the state is a per-binding fact
/// observed within one function's events. Requiring one producer spelling as
/// a text anchor keeps such rules from retaining every file that merely
/// mentions the sink callee (`get`), without changing what matches.
fn add_lifecycle_producer_anchors(prepared: &mut PreparedRule<'_>, typing: &RulepackTyping) {
    let Some(specs) = typing.lifecycle_specs_for(&prepared.rule.language) else {
        return;
    };
    for constraint in &prepared.rule.constraints.0 {
        let ConstraintKind::RequiresState { requires_state } = constraint else {
            continue;
        };
        let mut producers: Vec<String> = Vec::new();
        for spec in specs.iter().filter(|spec| spec.state == requires_state.expected) {
            let Some(group) = text_anchor_groups_for_target(&spec.target, MatchKind::Call)
                .into_iter()
                .next()
            else {
                continue;
            };
            for anchor in group {
                if !producers.contains(&anchor) {
                    producers.push(anchor);
                }
            }
        }
        if !producers.is_empty() {
            prepared.text_anchor_groups.push(producers);
        }
    }
}

fn text_anchor_groups_for_rule(rule: &Rule, target: &RuleTarget) -> Vec<Vec<String>> {
    let mut groups = Vec::new();
    groups.extend(text_anchor_groups_for_target(target, rule.match_spec.kind));
    // `in_class` means "equals or extends" and may be satisfied through an
    // arbitrarily deep base chain declared in other files. Requiring the
    // named base spelling in this file would be a lossy raw-text prefilter.
    // The staged compiler matcher enforces it against exact declaration
    // ownership after receiver ancestry has been loaded.
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
                // Decorator config facts are compiler-semantic identities,
                // not source spellings. For example, an adapter may lower
                // `@job(bind=True)` to `job.bind=true`. Requiring the latter
                // verbatim here would make this conservative raw-text planner
                // language- and spelling-sensitive. Only the callable segment
                // before config remains a source anchor; exact config is
                // checked later against adapter facts.
                let callable = decorator
                    .split('.')
                    .take_while(|segment| !segment.contains('='))
                    .last()
                    .unwrap_or_default();
                push_text_anchor(&mut decorator_group, annotation_tail(callable));
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

fn package_text_anchors_for_rule(rule: &Rule, target: &RuleTarget, package_signals: &[&str]) -> Vec<String> {
    if package_signals.is_empty() || !rule_requires_call_package_signal(rule) {
        return Vec::new();
    }
    // Exact enclosing-owner source rules prove provider identity only after
    // the compiler body and ancestry are available. A package spelling is
    // not required to occur in the same file, so retaining it as a raw-text
    // prerequisite would discard the candidate before that structural proof.
    if rule.kind == crate::rule::RuleKind::Source
        && (!target.in_class.is_empty() || !target.in_owner_base.is_empty())
    {
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
        if call_text_match_is_call(text, start, end, syntax) {
            return true;
        }
        search_from = end;
        if search_from >= text.len() {
            break;
        }
    }
    false
}

fn call_text_match_is_call(text: &str, start: usize, end: usize, syntax: CallTextPrefilter) -> bool {
    let before_ok = text[..start]
        .chars()
        .next_back()
        .is_none_or(|ch| !is_call_identifier_char(ch));
    before_ok
        && (call_anchor_followed_by_call_paren(text, end)
            || (syntax == CallTextPrefilter::ParenthesizedOrCommand
                && call_anchor_followed_by_command_style_call(text, end)))
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
        for (idx, part) in attribute.iter().enumerate() {
            // A two-part target's leading component may be a receiver type,
            // module alias, or static-import owner that is absent from the
            // call spelling. The compact syntax header performs the exact
            // structured comparison after this raw-source candidate gate, so
            // require only the terminal component here. Identifier case is a
            // convention in many languages and is never semantic evidence.
            if attribute.len() == 2 && idx == 0 {
                continue;
            }
            let components = bonsai_common::qualified_name_segments(part);
            if components.len() > 1 {
                // A single rule component may preserve an exact multipart
                // callable suffix. Its identifier components are each
                // mandatory in source, but the complete compiler spelling is
                // not necessarily contiguous around argument expressions.
                // Keep one required raw-anchor group per structural component
                // and leave the exact suffix comparison to the body matcher.
                for component in components {
                    let mut out = Vec::new();
                    push_text_anchor(&mut out, component);
                    if !out.is_empty() {
                        groups.push(out);
                    }
                }
            } else {
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
    if let Some(default_call) = target.default_call.as_deref() {
        let mut out = Vec::new();
        push_text_anchor(&mut out, bonsai_common::short_qualified_tail(default_call));
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
    rule.analysis_semantics
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

fn local_import_package_signal_marker(package: &str) -> String {
    format!("{LOCAL_IMPORT_PACKAGE_SIGNAL_PREFIX}:{package}")
}

fn workspace_import_package_marker(package: &str) -> String {
    format!("{WORKSPACE_IMPORT_PACKAGE_PREFIX}:{package}")
}

fn component_import_package_marker(package: &str) -> String {
    format!("{COMPONENT_IMPORT_PACKAGE_PREFIX}:{package}")
}

fn manifest_package_marker(package: &str) -> String {
    format!("{MANIFEST_PACKAGE_PREFIX}:{package}")
}

fn template_manifest_package_marker(package: &str) -> String {
    format!("{TEMPLATE_MANIFEST_PACKAGE_PREFIX}:{package}")
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum PackageEvidenceScope {
    Direct,
    Component,
    Manifest,
    TemplateManifest,
}

/// Exact package evidence queried by the endpoint matcher.
///
/// The materialized implementation preserves the legacy marker-set oracle
/// used by focused tests and isolated checks. Broad scans use the compact
/// implementation below, which borrows shared component/manifest sets and
/// therefore changes allocation only, never package ownership semantics.
trait PackageEvidence {
    fn contains_import(
        &self,
        signal: &str,
        scope: PackageEvidenceScope,
        semantics: &crate::loader::PackageMatchSemantics,
    ) -> bool;

    fn local_import_allows(&self, candidate: &str, signal: &str) -> bool;

    fn has_local_import_package(&self, signal: &str) -> bool;
}

fn is_package_evidence_marker(candidate: &str) -> bool {
    candidate.starts_with(LOCAL_IMPORT_PACKAGE_PREFIX)
        || candidate.starts_with(LOCAL_IMPORT_PACKAGE_SIGNAL_PREFIX)
        || candidate.starts_with(WORKSPACE_IMPORT_PACKAGE_PREFIX)
        || candidate.starts_with(COMPONENT_IMPORT_PACKAGE_PREFIX)
        || candidate.starts_with(MANIFEST_PACKAGE_PREFIX)
        || candidate.starts_with(TEMPLATE_MANIFEST_PACKAGE_PREFIX)
}

impl PackageEvidence for AHashSet<String> {
    fn contains_import(
        &self,
        signal: &str,
        scope: PackageEvidenceScope,
        semantics: &crate::loader::PackageMatchSemantics,
    ) -> bool {
        let scope_prefix = match scope {
            PackageEvidenceScope::Direct => None,
            PackageEvidenceScope::Component => Some(COMPONENT_IMPORT_PACKAGE_PREFIX),
            PackageEvidenceScope::Manifest => Some(MANIFEST_PACKAGE_PREFIX),
            PackageEvidenceScope::TemplateManifest => Some(TEMPLATE_MANIFEST_PACKAGE_PREFIX),
        };
        self.iter().any(|candidate| {
            let candidate = if let Some(prefix) = scope_prefix {
                let Some(candidate) = candidate
                    .strip_prefix(prefix)
                    .and_then(|candidate| candidate.strip_prefix(':'))
                else {
                    return false;
                };
                candidate
            } else {
                if is_package_evidence_marker(candidate) {
                    return false;
                }
                candidate.as_str()
            };
            crate::pkg::import_matches_package(candidate, signal, semantics)
        })
    }

    fn local_import_allows(&self, candidate: &str, signal: &str) -> bool {
        self.contains(&local_import_package_marker(candidate, signal))
            || call_head(candidate)
                .is_some_and(|head| self.contains(&local_import_package_marker(head, signal)))
    }

    fn has_local_import_package(&self, signal: &str) -> bool {
        self.contains(&local_import_package_signal_marker(signal))
    }
}

fn package_set_contains_import<P: PackageEvidence + ?Sized>(
    file_packages: &P,
    signal: &str,
    scope_prefix: Option<&str>,
    semantics: &crate::loader::PackageMatchSemantics,
) -> bool {
    let scope = match scope_prefix {
        None => PackageEvidenceScope::Direct,
        Some(COMPONENT_IMPORT_PACKAGE_PREFIX) => PackageEvidenceScope::Component,
        Some(MANIFEST_PACKAGE_PREFIX) => PackageEvidenceScope::Manifest,
        Some(TEMPLATE_MANIFEST_PACKAGE_PREFIX) => PackageEvidenceScope::TemplateManifest,
        Some(_) => return false,
    };
    file_packages.contains_import(signal, scope, semantics)
}

fn local_import_package_allows<P: PackageEvidence + ?Sized>(
    file_packages: &P,
    candidate: &str,
    signal: &str,
) -> bool {
    file_packages.local_import_allows(candidate, signal)
}

fn file_packages_have_local_import_package<P: PackageEvidence + ?Sized>(
    file_packages: &P,
    signal: &str,
) -> bool {
    file_packages.has_local_import_package(signal)
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
    /// Stable order used by the raw-anchor planner. Each file carries only
    /// the indexes that survived its exact raw syntax anchors into the
    /// import/package stage, avoiding a second rule-by-file scan.
    text_order_rules: Vec<&'p PreparedRule<'rule>>,
    /// Exact equivalence classes for the package-evidence predicate. Broad
    /// packs commonly have many sink variants for one provider, so this lets
    /// each file answer that shared import/package question once.
    text_order_package_classes: Vec<usize>,
    package_evidence_representatives: Vec<&'p PreparedRule<'rule>>,
    call_rules: Vec<&'p PreparedRule<'rule>>,
    call_wildcard_rules: Vec<&'p PreparedRule<'rule>>,
    call_keyed_rules: AHashMap<String, Vec<&'p PreparedRule<'rule>>>,
    read_rules: Vec<&'p PreparedRule<'rule>>,
    read_wildcard_rules: Vec<&'p PreparedRule<'rule>>,
    read_keyed_rules: AHashMap<String, Vec<&'p PreparedRule<'rule>>>,
    write_rules: Vec<&'p PreparedRule<'rule>>,
    param_rules: Vec<&'p PreparedRule<'rule>>,
    type_rules: Vec<&'p PreparedRule<'rule>>,
    return_rules: Vec<&'p PreparedRule<'rule>>,
    missing_rules: Vec<&'p PreparedRule<'rule>>,
    /// Rulepack call-result, constructor, and callback typing for this run.
    factory: Arc<RulepackTyping>,
    include_workspace_package_context: bool,
    workspace_package_signals: Vec<String>,
    /// One multi-pattern scan replaces the rule x source-bytes Cartesian
    /// product for literal target/package anchors. Exact syntax, package, and
    /// semantic matching still happens in the compiler-header/body stages.
    text_anchor_ids: AHashMap<String, usize>,
    text_anchor_matcher: Option<AhoCorasick>,
    call_text_anchor_ids: Vec<bool>,
}

struct BatchTextAnchorMatches {
    present: Vec<bool>,
    call_like: Vec<bool>,
    syntax_rule_indexes: Vec<usize>,
}

struct FileRuleFilterContext<'a> {
    ws: &'a Workspace,
    file: FileId,
    text: &'a str,
    mode: ConstraintMode,
    retention: FactRetention,
    prewarmed_import_contexts: Option<&'a Arc<LanguageImportPackageContexts>>,
    compiler_imports: Option<&'a bonsai_lang_api::ImportIndex>,
    matched_text_anchors: Option<&'a BatchTextAnchorMatches>,
}

impl<'p, 'rule> PreparedRuleBatch<'p, 'rule> {
    fn new(rules: &[&'p PreparedRule<'rule>], factory: Arc<RulepackTyping>) -> Self {
        let text_order_rules = rules
            .iter()
            .copied()
            .filter(|rule| rule.rule.match_spec.kind != MatchKind::Missing)
            .collect::<Vec<_>>();
        let mut package_evidence_representatives = Vec::new();
        let text_order_package_classes = text_order_rules
            .iter()
            .map(|rule| {
                package_evidence_representatives
                    .iter()
                    .position(|representative: &&PreparedRule<'_>| {
                        rule.has_same_package_evidence_query(representative)
                    })
                    .unwrap_or_else(|| {
                        package_evidence_representatives.push(*rule);
                        package_evidence_representatives.len() - 1
                    })
            })
            .collect::<Vec<_>>();
        let mut text_anchors = rules
            .iter()
            .flat_map(|rule| {
                rule.text_anchor_groups
                    .iter()
                    .flatten()
                    .chain(rule.package_text_anchors.iter())
                    .chain(rule.call_text_anchor.iter())
            })
            .cloned()
            .collect::<Vec<_>>();
        text_anchors.sort();
        text_anchors.dedup();
        let text_anchor_ids: AHashMap<String, usize> = text_anchors
            .iter()
            .enumerate()
            .map(|(index, anchor)| (anchor.clone(), index))
            .collect();
        let text_anchor_matcher = (!text_anchors.is_empty())
            .then(|| AhoCorasick::new(&text_anchors).ok())
            .flatten();
        let mut call_text_anchor_ids = vec![false; text_anchors.len()];
        for anchor in rules.iter().filter_map(|rule| rule.call_text_anchor.as_ref()) {
            if let Some(index) = text_anchor_ids.get(anchor) {
                call_text_anchor_ids[*index] = true;
            }
        }
        let mut out = Self {
            text_order_rules,
            text_order_package_classes,
            package_evidence_representatives,
            call_rules: Vec::new(),
            call_wildcard_rules: Vec::new(),
            call_keyed_rules: AHashMap::new(),
            read_rules: Vec::new(),
            read_wildcard_rules: Vec::new(),
            read_keyed_rules: AHashMap::new(),
            write_rules: Vec::new(),
            param_rules: Vec::new(),
            type_rules: Vec::new(),
            return_rules: Vec::new(),
            missing_rules: Vec::new(),
            factory,
            include_workspace_package_context: rules
                .iter()
                .any(|rule| rule.needs_workspace_package_context()),
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
            text_anchor_ids,
            text_anchor_matcher,
            call_text_anchor_ids,
        };
        for &rule in rules {
            match rule.rule.match_spec.kind {
                MatchKind::Call | MatchKind::New => {
                    out.call_rules.push(rule);
                    insert_call_rule_index(&mut out.call_keyed_rules, &mut out.call_wildcard_rules, rule);
                }
                MatchKind::Read => {
                    out.read_rules.push(rule);
                    insert_call_rule_index(&mut out.read_keyed_rules, &mut out.read_wildcard_rules, rule);
                }
                MatchKind::Write => out.write_rules.push(rule),
                MatchKind::Param => out.param_rules.push(rule),
                MatchKind::Type => out.type_rules.push(rule),
                MatchKind::Return => out.return_rules.push(rule),
                MatchKind::Missing => out.missing_rules.push(rule),
            }
        }
        out
    }

    fn text_anchor_matches(
        &self,
        text: &str,
        syntax: CallTextPrefilter,
        mode: ConstraintMode,
    ) -> BatchTextAnchorMatches {
        let mut matched = BatchTextAnchorMatches {
            present: vec![false; self.text_anchor_ids.len()],
            call_like: vec![false; self.text_anchor_ids.len()],
            syntax_rule_indexes: Vec::new(),
        };
        if let Some(matcher) = self.text_anchor_matcher.as_ref() {
            for found in matcher.find_overlapping_iter(text) {
                let index = found.pattern().as_usize();
                matched.present[index] = true;
                if self.call_text_anchor_ids[index]
                    && !matched.call_like[index]
                    && call_text_match_is_call(text, found.start(), found.end(), syntax)
                {
                    matched.call_like[index] = true;
                }
            }
        }
        for (index, rule) in self.text_order_rules.iter().enumerate() {
            if rule.syntax_target_possible_in_mode_with_anchor_lookup(
                text,
                mode,
                syntax,
                &|anchor| self.text_anchor_present(text, &matched, anchor),
                &|anchor| self.call_text_anchor_present(text, &matched, anchor, syntax),
            ) {
                matched.syntax_rule_indexes.push(index);
            }
        }
        matched
    }

    fn text_anchor_present(&self, text: &str, matched: &BatchTextAnchorMatches, anchor: &str) -> bool {
        self.text_anchor_ids
            .get(anchor)
            .and_then(|index| matched.present.get(*index))
            .copied()
            // A missing index or failed matcher construction must only cost
            // work; it must never suppress a valid rule match.
            .unwrap_or_else(|| text.contains(anchor))
    }

    fn call_text_anchor_present(
        &self,
        text: &str,
        matched: &BatchTextAnchorMatches,
        anchor: &str,
        syntax: CallTextPrefilter,
    ) -> bool {
        self.text_anchor_ids
            .get(anchor)
            .and_then(|index| matched.call_like.get(*index))
            .copied()
            .unwrap_or_else(|| call_text_anchor_possible_in(text, anchor, syntax))
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
            matched_text_anchors,
        } = context;
        let include_workspace_package_context = self.include_workspace_package_context
            && (!matches!(mode, ConstraintMode::Inventory)
                || workspace_manifest_package_context_allowed(ws, file));
        let call_text_prefilter = ws
            .db()
            .adapter_for(file)
            .map(|adapter| adapter.capabilities().call_text_prefilter)
            .unwrap_or_default();
        let computed_text_anchors = matched_text_anchors
            .is_none()
            .then(|| self.text_anchor_matches(text, call_text_prefilter, mode));
        let matched_text_anchors = matched_text_anchors
            .or(computed_text_anchors.as_ref())
            .expect("text anchor evidence is supplied or computed");
        let anchor_present = |anchor: &str| self.text_anchor_present(text, matched_text_anchors, anchor);
        let mut package_planning_evidence = None;
        let mut package_evidence_by_class = vec![None; self.package_evidence_representatives.len()];
        let mut rules = Vec::new();
        for &rule_index in &matched_text_anchors.syntax_rule_indexes {
            let Some(&rule) = self.text_order_rules.get(rule_index) else {
                continue;
            };
            let package_possible = rule.package_text_anchors.is_empty()
                || rule
                    .package_text_anchors
                    .iter()
                    .any(|anchor| anchor_present(anchor))
                // An exact typed parameter can prove external identity in the
                // body phase even when a runtime-injected source file carries
                // no import. Keep only files containing one of the rule's
                // declared type spellings; the compiler matcher still checks
                // the parameter binding and rejects workspace/import
                // collisions before emitting a match.
                || (rule.requires_call_package_signal
                    && rule.rule.match_spec.kind == MatchKind::Param
                    && rule
                        .rule
                        .match_spec
                        .target
                        .as_ref()
                        .is_some_and(|target| {
                            (!target.param_type_in.is_empty()
                                || !target.param_type_exact_in.is_empty())
                                && target
                                    .param_type_in
                                    .iter()
                                    .chain(target.param_type_exact_in.iter())
                                    .any(|type_name| anchor_present(type_name))
                        }))
                || {
                    let evidence = package_planning_evidence.get_or_insert_with(|| {
                        file_package_planning_evidence(
                            ws,
                            file,
                            include_workspace_package_context,
                            retention,
                            prewarmed_import_contexts,
                            compiler_imports,
                        )
                    });
                    let class = self.text_order_package_classes[rule_index];
                    *package_evidence_by_class[class].get_or_insert_with(|| {
                        self.package_evidence_representatives[class]
                            .package_evidence_allows_text_anchor_skip_in_planning(evidence)
                    })
                };
            if package_possible {
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

    /// Narrow call/new and return rules with exact adapter-emitted syntax
    /// targets before decoding declaration and flow bodies. Other non-call
    /// rules remain untouched.
    ///
    /// The projection deliberately over-approximates declaration scope by
    /// combining file-local aliases. That can retain extra bodies, but it
    /// cannot suppress a match that the full matcher would emit.
    fn filtered_rule_refs_for_syntax_header(
        &self,
        rules: Vec<&'p PreparedRule<'rule>>,
        syntax: &CompilerSyntaxHeader,
        source_text: &str,
        compiler_imports: Option<&bonsai_lang_api::ImportIndex>,
        language: &str,
        receiver_ancestry_complete: bool,
    ) -> (Vec<&'p PreparedRule<'rule>>, bool, bool) {
        let mut alias_map = compiler_imports
            .map(bonsai_lang_api::alias_map_from_imports)
            .unwrap_or_default();
        extend_alias_map_with_declared_types(&mut alias_map, &syntax.type_aliases);
        extend_alias_map_with_compiler_assignment_aliases(&mut alias_map, &syntax.assignment_aliases);
        let mut workspace_call_resolution_required = false;
        if let Some(specs) = self.factory.specs_for(language) {
            let mut factory_aliases = Vec::new();
            // Factory results form a finite monotone relation over the
            // compiler header's assignment targets. Derive it to the same
            // uncapped fixed point as the full-body matcher: a chain such as
            // `connect() -> DB`, then `db.prepare() -> Statement` must not be
            // discarded by header planning before the exact body can prove
            // its terminal receiver.
            loop {
                let prior_len = factory_aliases.len();
                for assignment in &syntax.factory_assignments {
                    let expanded = expand_callee_alias(&assignment.call_name, &alias_map);
                    for spec in specs {
                        if !typing_imports_allow(&spec.required_imports, compiler_imports) {
                            continue;
                        }
                        if !factory_spec_matches_call(
                            &assignment.call_name,
                            assignment.call_receiver.as_deref(),
                            spec,
                            &alias_map,
                        ) && !expanded.as_deref().is_some_and(|expanded| {
                            factory_spec_matches_call(expanded, None, spec, &alias_map)
                        }) {
                            continue;
                        }
                        if spec.kind == MatchKind::New {
                            workspace_call_resolution_required = true;
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
                if factory_aliases.len() == prior_len {
                    break;
                }
                extend_alias_map_with_declared_types(&mut alias_map, &factory_aliases[prior_len..]);
            }
        }
        let callback_aliases = synth_callback_param_type_aliases_from_header(
            syntax,
            &self.factory,
            language,
            &alias_map,
            compiler_imports,
        );
        extend_alias_map_with_declared_types(&mut alias_map, &callback_aliases);
        // Workspace return-type resolution can affect a receiver match only
        // when the receiver is the exact result of a compiler-recorded call
        // assignment (possibly copied through exact assignment aliases).
        // Merely seeing an untyped receiver such as `client.clean()` is not
        // evidence that `client` came from a call; opening global declaration
        // headers for every such call defeats syntax-header planning.
        let mut call_result_targets = syntax
            .factory_assignments
            .iter()
            .map(|assignment| normalize_leading_call_punctuation(&assignment.target).to_string())
            .collect::<AHashSet<_>>();
        loop {
            let prior_len = call_result_targets.len();
            for assignment in &syntax.assignment_aliases {
                let source = normalize_leading_call_punctuation(&assignment.source);
                if call_result_targets.contains(source) {
                    call_result_targets
                        .insert(normalize_leading_call_punctuation(&assignment.target).to_string());
                }
            }
            if call_result_targets.len() == prior_len {
                break;
            }
        }
        // Call/new planning used to compare every surviving rule with every
        // adapter-emitted call. Large files and broad language packs turned
        // that into a rule x call Cartesian product even though the body
        // matcher already maintains an exact callee-keyed candidate index.
        // Reuse that same index here, then restore the input rule order below.
        // Wildcard/regex rules remain in `call_wildcard_rules`, so this only
        // changes scheduling cost; it cannot remove a possible exact match.
        let allowed_call_rule_ids = rules
            .iter()
            .filter(|prepared| matches!(prepared.rule.match_spec.kind, MatchKind::Call | MatchKind::New))
            .map(|prepared| prepared.rule.id.as_str())
            .collect::<AHashSet<_>>();
        let mut matched_call_rule_ids = AHashSet::new();
        let mut receiver_ancestry_deferred = false;
        let mut call_candidates = Vec::new();
        for call in &syntax.calls {
            call_candidates.clear();
            push_call_candidate_rules(&mut call_candidates, self, &call.name, &alias_map);
            for prepared in call_candidates
                .iter()
                .copied()
                .filter(|prepared| allowed_call_rule_ids.contains(prepared.rule.id.as_str()))
            {
                let call_kind_matches = prepared.call_kind_allows(call.call_kind);
                let matched_callee = if call_kind_matches
                    && prepared.name.is_none()
                    && prepared.attribute.is_none()
                    && prepared.regex.is_none()
                {
                    Some(call.name.clone())
                } else if call_kind_matches {
                    callee_or_alias_matches(
                        &call.name,
                        &call.receiver_types,
                        prepared.name,
                        prepared.attribute,
                        prepared.regex.as_ref(),
                        &alias_map,
                    )
                } else {
                    None
                };
                let direct_match = matched_callee.as_ref().is_some_and(|matched_callee| {
                    prepared.base_name_allows(matched_callee)
                        && (prepared.rule.match_spec.kind != MatchKind::New
                            || call.call_kind == CallKind::Constructor
                            || rulepack_constructor_matches_call(
                                &self.factory,
                                language,
                                &call.name,
                                call.receiver.as_deref(),
                                &alias_map,
                                compiler_imports,
                            ))
                });
                if !receiver_ancestry_complete
                    && receiver_ancestry_can_change_call_match(prepared, call, direct_match)
                {
                    receiver_ancestry_deferred = true;
                }
                if direct_match
                    && prepared.rule.match_spec.kind == MatchKind::New
                    && call.call_kind != CallKind::Constructor
                {
                    workspace_call_resolution_required = true;
                }
                // A typed receiver with no adapter-proven type may be the
                // exact result of a first-party call, including a value
                // exported by an imported module. The compact syntax header
                // proves that this endpoint survived name/kind filtering;
                // request the independently decodable workspace declaration
                // headers so the body matcher can resolve that call chain.
                // This is deliberately syntax-generic: provider/API names
                // remain rule data and ambiguous callable identities fail
                // closed in `workspace_call_return_type`.
                if direct_match
                    && call.receiver.as_deref().is_some_and(|receiver| {
                        call_result_targets.contains(normalize_leading_call_punctuation(receiver))
                    })
                    && call.receiver_types.is_empty()
                    && DeclFactRequirements::for_rules(std::iter::once(prepared))
                        .contains(DeclFactRequirements::CALL_RESULT_TYPES)
                {
                    workspace_call_resolution_required = true;
                }
                if direct_match {
                    matched_call_rule_ids.insert(prepared.rule.id.as_str());
                }
            }
        }
        let mut retained = Vec::new();
        for prepared in rules {
            match prepared.rule.match_spec.kind {
                MatchKind::Return => {
                    if return_rule_possible_in_syntax_header(prepared, syntax, source_text) {
                        retained.push(prepared);
                    }
                }
                MatchKind::Call | MatchKind::New => {
                    if matched_call_rule_ids.contains(prepared.rule.id.as_str()) {
                        retained.push(prepared);
                    }
                }
                MatchKind::Read
                | MatchKind::Write
                | MatchKind::Param
                | MatchKind::Type
                | MatchKind::Missing => {
                    retained.push(prepared);
                }
            }
        }
        if !receiver_ancestry_complete
            && retained.iter().any(|prepared| {
                prepared
                    .rule
                    .match_spec
                    .target
                    .as_ref()
                    .is_some_and(|target| !target.in_class.is_empty() || !target.in_class_suffix.is_empty())
            })
        {
            // Declaration-scoped rules (parameters, reads, and calls with an
            // `in_class` guard) need the same exact cross-file ancestry as
            // receiver-constrained calls. A compact syntax header cannot
            // prove ownership for a non-call target, so keep the candidate
            // until ancestry enriches its streamed compiler body.
            receiver_ancestry_deferred = true;
        }
        (
            retained,
            receiver_ancestry_deferred,
            workspace_call_resolution_required,
        )
    }

    /// Return whether any rule in this language batch can match the raw file
    /// text before imports or full adapter IR are decoded.
    fn syntax_target_possible_in_text_with_matches(
        &self,
        _text: &str,
        _mode: ConstraintMode,
        _call_text_prefilter: CallTextPrefilter,
        matched_text_anchors: &BatchTextAnchorMatches,
    ) -> bool {
        !self.missing_rules.is_empty() || !matched_text_anchors.syntax_rule_indexes.is_empty()
    }
}

/// Lossless body-planning gate for `kind: return` rules.
///
/// The full matcher accepts either an adapter-lowered return spelling, the
/// exact return source span, or the exact RHS of a uniquely reaching local
/// assignment. The independent syntax header retains all compiler-proven RHS
/// candidates only for scheduling; full matching still proves control-flow
/// uniqueness. No whole-file text search or language/API vocabulary is used.
fn return_rule_possible_in_syntax_header(
    prepared: &PreparedRule<'_>,
    syntax: &CompilerSyntaxHeader,
    source_text: &str,
) -> bool {
    if let Some(regex) = prepared.regex.as_ref() {
        for returned in &syntax.returns {
            if [returned.value_text.as_deref(), returned.value_name.as_deref()]
                .into_iter()
                .flatten()
                .any(|candidate| regex.is_match(candidate))
            {
                return true;
            }
            let Ok(start) = usize::try_from(returned.span.start) else {
                return true;
            };
            let Ok(end) = usize::try_from(returned.span.end) else {
                return true;
            };
            let Some(span_text) = source_text.get(start..end) else {
                // A malformed or stale scheduling header must cost work, not
                // suppress a full-body match.
                return true;
            };
            if regex.is_match(span_text) {
                return true;
            }
            for assignment_value_span in &returned.assignment_value_spans {
                let Ok(start) = usize::try_from(assignment_value_span.start) else {
                    return true;
                };
                let Ok(end) = usize::try_from(assignment_value_span.end) else {
                    return true;
                };
                let Some(assignment_value) = source_text.get(start..end) else {
                    // Header/source disagreement can only increase work; it
                    // must never suppress a full-body return match.
                    return true;
                };
                if regex.is_match(assignment_value) {
                    return true;
                }
            }
        }
    }
    if let Some(name) = prepared.name {
        return syntax.returns.iter().any(|returned| {
            returned.value_name.as_deref() == Some(name)
                || returned
                    .value_text
                    .as_deref()
                    .is_some_and(|value| value.trim() == name)
        });
    }
    prepared.name.is_none()
        && prepared.regex.is_none()
        && prepared.attribute.is_none()
        && !syntax.returns.is_empty()
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
    factory: &Arc<RulepackTyping>,
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
    regex_terminal_call_keys(pattern)
}

fn rule_target_regex_text(rule: &Rule) -> Option<&str> {
    let target = match rule.match_spec.kind {
        MatchKind::Call | MatchKind::New | MatchKind::Missing => rule.match_spec.callee.as_ref(),
        MatchKind::Read | MatchKind::Write | MatchKind::Return | MatchKind::Param | MatchKind::Type => {
            rule.match_spec.target.as_ref()
        }
    }?;
    target.regex.as_deref()
}

fn regex_terminal_call_key(pattern: &str) -> Option<String> {
    let keys = regex_terminal_call_keys(pattern);
    let [key] = keys.as_slice() else {
        return None;
    };
    Some(key.clone())
}

/// Return every exact terminal callable/read identity admitted by a regex.
///
/// The candidate index is a scheduling optimization, so it may narrow only
/// when every regex branch has an exact terminal key. Parsing the regex HIR
/// avoids treating the textual suffix of the final alternative as though it
/// applied to every branch (for example `.(foo|bar)$|.baz$`).
fn regex_terminal_call_keys(pattern: &str) -> Vec<String> {
    let trimmed = pattern.trim();
    // The candidate map is byte-case-sensitive. A case-insensitive target
    // therefore stays in the wildcard bucket unless/until the index itself
    // carries case-folded keys; keying its displayed suffix could suppress a
    // valid differently-cased compiler identity.
    if trimmed.starts_with("(?i)") {
        return Vec::new();
    }
    let trimmed = trimmed.strip_prefix("(?-i)").unwrap_or(trimmed);
    let Ok(hir) = regex_syntax::Parser::new().parse(trimmed) else {
        return Vec::new();
    };
    terminal_hir_call_keys(&hir, true).unwrap_or_default()
}

fn terminal_hir_call_keys(hir: &regex_syntax::hir::Hir, boundary_before: bool) -> Option<Vec<String>> {
    use regex_syntax::hir::HirKind;

    match hir.kind() {
        HirKind::Literal(literal) => {
            let text = std::str::from_utf8(&literal.0).ok()?;
            let starts_at_boundary = text.chars().next().is_some_and(|ch| !is_call_identifier_char(ch));
            if !boundary_before && !starts_at_boundary {
                return None;
            }
            terminal_literal_call_key(text).map(|key| vec![key])
        }
        HirKind::Capture(capture) => terminal_hir_call_keys(&capture.sub, boundary_before),
        HirKind::Alternation(branches) => {
            let mut keys = Vec::new();
            for branch in branches {
                for key in terminal_hir_call_keys(branch, boundary_before)? {
                    if !keys.contains(&key) {
                        keys.push(key);
                    }
                }
            }
            keys.sort();
            (!keys.is_empty()).then_some(keys)
        }
        HirKind::Concat(parts) => {
            let (terminal_index, terminal) = parts
                .iter()
                .enumerate()
                .rev()
                .find(|(_, part)| !matches!(part.kind(), HirKind::Empty | HirKind::Look(_)))?;
            let prefix = &parts[..terminal_index];
            let has_prefix = prefix
                .iter()
                .any(|part| !matches!(part.kind(), HirKind::Empty | HirKind::Look(_)));
            let terminal_boundary = if !has_prefix {
                boundary_before
            } else {
                hir_sequence_ends_with_name_boundary(prefix)
            };
            terminal_hir_call_keys(terminal, terminal_boundary)
        }
        HirKind::Repetition(repetition) if repetition.min == 1 && repetition.max == Some(1) => {
            terminal_hir_call_keys(&repetition.sub, boundary_before)
        }
        HirKind::Empty | HirKind::Look(_) | HirKind::Class(_) | HirKind::Repetition(_) => None,
    }
}

fn hir_sequence_ends_with_name_boundary(parts: &[regex_syntax::hir::Hir]) -> bool {
    use regex_syntax::hir::HirKind;

    parts
        .iter()
        .rev()
        .find_map(|part| match part.kind() {
            HirKind::Empty => None,
            // A zero-width boundary/start assertion separates the following
            // terminal from any preceding identifier just as an explicit
            // member punctuation literal does.
            HirKind::Look(_) => Some(true),
            _ => Some(hir_ends_with_name_boundary(part)),
        })
        .unwrap_or(false)
}

fn hir_ends_with_name_boundary(hir: &regex_syntax::hir::Hir) -> bool {
    use regex_syntax::hir::HirKind;

    match hir.kind() {
        HirKind::Literal(literal) => std::str::from_utf8(&literal.0)
            .ok()
            .and_then(|text| text.chars().next_back())
            .is_some_and(|ch| !is_call_identifier_char(ch)),
        HirKind::Capture(capture) => hir_ends_with_name_boundary(&capture.sub),
        HirKind::Alternation(branches) => {
            !branches.is_empty() && branches.iter().all(hir_ends_with_name_boundary)
        }
        HirKind::Concat(parts) => hir_sequence_ends_with_name_boundary(parts),
        HirKind::Repetition(repetition) if repetition.min > 0 => hir_ends_with_name_boundary(&repetition.sub),
        HirKind::Look(_) => true,
        HirKind::Empty | HirKind::Class(_) | HirKind::Repetition(_) => false,
    }
}

fn terminal_literal_call_key(literal: &str) -> Option<String> {
    let mut start = literal.len();
    let bytes = literal.as_bytes();
    while start > 0 {
        let byte = bytes[start - 1];
        if byte == b'_' || byte == b'$' || byte.is_ascii_alphanumeric() {
            start -= 1;
            continue;
        }
        break;
    }
    let key = literal
        .get(start..)?
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
        let started = ctx.debug_timings.map(|_| Instant::now());
        scan_refs_batch(
            ctx,
            rules,
            RefKind::Read,
            rules.include_workspace_package_context,
            &rules.factory,
            out,
        );
        if let (Some(started), Some(timings)) = (started, ctx.debug_timings) {
            record_elapsed_ns(&timings.refs_scan, started);
        }
        let started = ctx.debug_timings.map(|_| Instant::now());
        scan_flow_reads_batch(
            ctx,
            rules,
            rules.include_workspace_package_context,
            &rules.factory,
            out,
        );
        if let (Some(started), Some(timings)) = (started, ctx.debug_timings) {
            record_elapsed_ns(&timings.flow_reads_scan, started);
        }
    }
    if !rules.write_rules.is_empty() {
        let started = ctx.debug_timings.map(|_| Instant::now());
        scan_writes_batch(ctx, rules, out);
        scan_ref_writes_batch(ctx, rules, out);
        if let (Some(started), Some(timings)) = (started, ctx.debug_timings) {
            record_elapsed_ns(&timings.writes_scan, started);
        }
    }
    if !rules.param_rules.is_empty() {
        let started = ctx.debug_timings.map(|_| Instant::now());
        scan_params_batch(
            ctx,
            &rules.param_rules,
            rules.include_workspace_package_context,
            out,
        );
        if let (Some(started), Some(timings)) = (started, ctx.debug_timings) {
            record_elapsed_ns(&timings.params_scan, started);
        }
    }
    if !rules.type_rules.is_empty() {
        let started = ctx.debug_timings.map(|_| Instant::now());
        scan_callable_types_batch(ctx, &rules.type_rules, out);
        if let (Some(started), Some(timings)) = (started, ctx.debug_timings) {
            record_elapsed_ns(&timings.types_scan, started);
        }
    }
    if !rules.return_rules.is_empty() {
        let started = ctx.debug_timings.map(|_| Instant::now());
        scan_returns_batch(ctx.ws, ctx.file, ctx.file_index, &rules.return_rules, out);
        if let (Some(started), Some(timings)) = (started, ctx.debug_timings) {
            record_elapsed_ns(&timings.returns_scan, started);
        }
    }
    if !rules.missing_rules.is_empty() {
        let started = ctx.debug_timings.map(|_| Instant::now());
        scan_missing_batch(
            ctx,
            &rules.missing_rules,
            rules.include_workspace_package_context,
            out,
        );
        if let (Some(started), Some(timings)) = (started, ctx.debug_timings) {
            record_elapsed_ns(&timings.missing_scan, started);
        }
    }
}

fn scan_callable_types_batch(
    ctx: &FileScanContext<'_, '_>,
    rules: &[&PreparedRule<'_>],
    out: &mut Vec<RuleMatch>,
) {
    let alias_map = file_alias_map_with_retention(ctx.ws, ctx.file, ctx.retention);
    for decl in &ctx.file_index.defs {
        for prepared in rules {
            if !typing_imports_allow(&prepared.rule.imports, ctx.file_imports) {
                continue;
            }
            let Some(target) = prepared.rule.match_spec.target.as_ref() else {
                continue;
            };
            let matched_type = decl
                .type_aliases
                .iter()
                .filter(|alias| alias.name == decl.name)
                .map(|alias| alias.type_name.as_str())
                .find(|type_name| callback_type_target_matches(type_name, target, &alias_map));
            let Some(matched_type) = matched_type else {
                continue;
            };
            let span = decl.name_span;
            let (file_path, line, column) = resolve_span(ctx.ws, ctx.file, span);
            out.push(RuleMatch {
                origin: MatchOrigin::Rulepack,
                rule_id: prepared.rule.id.clone(),
                language: prepared.rule.language.clone(),
                file: file_path,
                line,
                column,
                span,
                match_text: matched_type.to_string(),
                enclosing_fn: Some(decl.name.clone()),
            });
        }
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
        collect_return_rule_sites(&decl.flow_events, &mut returns);
        for return_site in returns {
            let ReturnRuleSite {
                span,
                value_kind,
                value_text,
                value_name,
                reaching_assignment,
            } = return_site;
            // A compiler-proven literal has no value carrier and therefore
            // cannot be a taint-relevant return boundary. Keep this in the
            // generic return matcher so rule YAML describes only the
            // security-sensitive output shape, not language-specific literal
            // spellings.
            if value_kind == Some(AssignValueKind::Literal) {
                continue;
            }
            let span_text = source_text
                .as_deref()
                .and_then(|text| text.get(span.start as usize..span.end as usize))
                .unwrap_or("");
            for prepared in rules {
                let direct_match =
                    return_rule_match(prepared, value_text.as_deref(), value_name.as_deref(), span_text);
                let assigned_match = direct_match.is_none().then(|| {
                    let assignment_span = reaching_assignment?;
                    let source = source_text.as_deref()?;
                    let rhs = assignment_values.rendering(assignment_span, source)?;
                    return_rule_match(prepared, Some(rhs), None, "")
                });
                let Some(match_text) = direct_match.or_else(|| assigned_match.flatten()) else {
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
    if prepared.name.is_none() && prepared.regex.is_none() && prepared.attribute.is_none() {
        return [value_text, value_name, Some(span_text)]
            .into_iter()
            .flatten()
            .map(str::trim)
            .find(|candidate| !candidate.is_empty())
            .map(str::to_string);
    }
    None
}

fn scan_params_batch(
    ctx: &FileScanContext<'_, '_>,
    rules: &[&PreparedRule<'_>],
    _include_workspace_package_context: bool,
    out: &mut Vec<RuleMatch>,
) {
    let ws = ctx.ws;
    let file = ctx.file;
    let file_index = ctx.file_index;
    let retention = ctx.retention;
    let file_packages = ctx.package_evidence;
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
            let param_types = decl
                .type_aliases
                .iter()
                .filter(|binding| binding.name == *param)
                .map(|binding| binding.type_name.clone())
                .collect::<Vec<_>>();
            // T204: per-param annotations are parallel-indexed with
            // `params`. Empty if the adapter doesn't surface them.
            let param_anns: &[String] = decl.param_annotations.get(idx).map(Vec::as_slice).unwrap_or(&[]);
            let param_default_calls: &[String] = decl
                .param_default_calls
                .get(idx)
                .map(Vec::as_slice)
                .unwrap_or(&[]);
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
                let want_default_call = target.and_then(|t| t.default_call.as_deref());
                let matched_annotation = want_annotation
                    .is_some_and(|want| param_anns.iter().any(|a| annotation_name_matches(a, want)));
                let matched_default_call = want_default_call.and_then(|want| {
                    param_default_calls
                        .iter()
                        .find(|callee| parameter_default_call_matches(callee, want, &alias_map))
                });
                let matched = if want_annotation.is_some() || want_default_call.is_some() {
                    // Parameter syntax selectors are alternatives. This lets
                    // one rule own both a decorator/annotation form and an
                    // equivalent direct default-call binder without teaching
                    // the adapter that either spelling is a framework API.
                    matched_annotation || matched_default_call.is_some()
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
                let package_context_allows = if let Some(default_call) = matched_default_call {
                    !parameter_default_call_is_shadowed(file_index, default_call)
                        && prepared.imported_default_call_context_allows(
                            default_call,
                            &alias_map,
                            file_packages,
                        )
                } else {
                    prepared.call_or_source_context_allows(
                        param,
                        &param_types,
                        &alias_map,
                        file_packages,
                        file_index,
                        Some(decl),
                    ) || unresolved_external_parameter_type_allows(
                        prepared,
                        &param_types,
                        &alias_map,
                        ctx.global_headers,
                    )
                };
                if !package_context_allows {
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
                    receiver: None,
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

/// Whether a package-gated parameter rule can use an exact unresolved type as
/// its external identity after compiler-owned collision checks.
///
/// Some runtimes inject framework request objects without a source-file import
/// (and partial source distributions may omit their build manifest). A typed
/// parameter is still exact evidence when its adapter-emitted type matches the
/// rule and no workspace declaration or conflicting compiler import owns that
/// spelling. This is deliberately limited to simple unresolved types:
/// provider-qualified types must satisfy the ordinary package/import gate.
fn unresolved_external_parameter_type_allows(
    prepared: &PreparedRule<'_>,
    actual_types: &[String],
    alias_map: &std::collections::HashMap<String, AliasTarget>,
    global_headers: Option<&GlobalIndex>,
) -> bool {
    if !prepared.requires_call_package_signal || prepared.rule.match_spec.kind != MatchKind::Param {
        return false;
    }
    let Some(target) = prepared.rule.match_spec.target.as_ref() else {
        return false;
    };
    if target.param_type_in.is_empty() && target.param_type_exact_in.is_empty() {
        return false;
    }
    let Some(global_headers) = global_headers else {
        return false;
    };

    let matching = actual_types
        .iter()
        .filter(|actual| {
            target
                .param_type_in
                .iter()
                .any(|want| semantic_type_names_match(actual, want))
                || target
                    .param_type_exact_in
                    .iter()
                    .any(|want| exact_semantic_type_names_match(actual, want))
        })
        .collect::<Vec<_>>();
    !matching.is_empty()
        && matching.into_iter().all(|actual| {
            let segments = bonsai_common::qualified_name_segments(actual);
            let Some(simple) = segments.last().copied() else {
                return false;
            };
            // A qualified compiler identity or an exact import binding has a
            // known provider. If that provider were rule-owned, the ordinary
            // package gate above would already have accepted it; otherwise it
            // is a collision and must fail closed.
            if segments.len() != 1 || alias_map.contains_key(simple) {
                return false;
            }
            !global_headers.find_by_name(simple).iter().any(|symbol| {
                global_headers.decl_of(*symbol).is_some_and(|decl| {
                    matches!(
                        decl.kind,
                        DeclKind::Class
                            | DeclKind::Struct
                            | DeclKind::Trait
                            | DeclKind::Interface
                            | DeclKind::Enum
                    )
                })
            })
        })
}

fn prepared_rule_needs_external_parameter_identity(prepared: &PreparedRule<'_>) -> bool {
    prepared.requires_call_package_signal
        && prepared.rule.match_spec.kind == MatchKind::Param
        && prepared
            .rule
            .match_spec
            .target
            .as_ref()
            .is_some_and(|target| !target.param_type_in.is_empty() || !target.param_type_exact_in.is_empty())
}

/// A module-level declaration with the same unqualified name wins over an
/// imported parameter-default factory in Python-style lexical binding. This
/// is a generic compiler identity check: framework/API meaning remains in the
/// rulepack, while the matcher refuses to attribute a locally shadowed call to
/// that external package.
fn parameter_default_call_is_shadowed(file_index: &DeclIndex, default_call: &str) -> bool {
    if bonsai_common::qualified_name_owner(default_call).is_some() {
        return false;
    }
    let name = bonsai_common::short_qualified_tail(default_call);
    file_index
        .defs
        .iter()
        .any(|decl| decl.parent.is_none() && decl.name == name)
}

fn parameter_default_call_matches(
    actual: &str,
    expected: &str,
    alias_map: &std::collections::HashMap<String, AliasTarget>,
) -> bool {
    let matches = |candidate: &str| {
        candidate == expected
            || bonsai_common::short_qualified_tail(candidate) == bonsai_common::short_qualified_tail(expected)
    };
    matches(actual)
        || expand_callee_alias(actual, alias_map)
            .as_deref()
            .is_some_and(matches)
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
        && target.in_class_suffix.is_empty()
        && target.in_owner_base.is_empty()
        && target.in_method.is_empty()
        && target.in_method_prefix.is_empty()
        && (param_index.is_none() || target.param_index_in.is_empty())
        && (param_index.is_none() || target.param_index_not_in.is_empty())
        && (param_index.is_none() || target.param_type_in.is_empty())
        && (param_index.is_none() || target.param_type_exact_in.is_empty())
        && target.param_default_calls_absent != Some(true)
        && target.signature_param_types.is_empty()
        && target.signature_param_annotations.is_empty()
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
        if target.param_default_calls_absent == Some(true)
            && decl
                .param_default_calls
                .get(idx)
                .is_some_and(|calls| !calls.is_empty())
        {
            return false;
        }
        if !target.param_index_in.is_empty() && !target.param_index_in.contains(&(idx as u32)) {
            return false;
        }
        if target.param_index_not_in.contains(&(idx as u32)) {
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
        if !target.param_type_exact_in.is_empty() {
            let Some(param_name) = decl.params.get(idx) else {
                return false;
            };
            let type_allowed = decl
                .type_aliases
                .iter()
                .filter(|binding| &binding.name == param_name)
                .any(|binding| {
                    target
                        .param_type_exact_in
                        .iter()
                        .any(|want| exact_semantic_type_names_match(&binding.type_name, want))
                });
            if !type_allowed {
                return false;
            }
        }
    }
    for requirement in &target.signature_param_types {
        if requirement.type_in.is_empty() {
            return false;
        }
        let Some(param_name) = decl.params.get(requirement.index as usize) else {
            return false;
        };
        let type_allowed = decl
            .type_aliases
            .iter()
            .filter(|binding| &binding.name == param_name)
            .any(|binding| {
                requirement
                    .type_in
                    .iter()
                    .any(|want| semantic_type_names_match(&binding.type_name, want))
            });
        if !type_allowed {
            return false;
        }
    }
    for requirement in &target.signature_param_annotations {
        if requirement.annotation_in.is_empty() {
            return false;
        }
        let Some(annotations) = decl.param_annotations.get(requirement.index as usize) else {
            return false;
        };
        if !requirement.annotation_in.iter().any(|want| {
            annotations
                .iter()
                .any(|actual| annotation_name_matches(actual, want))
        }) {
            return false;
        }
    }
    if !target.param_count_in.is_empty()
        && !target
            .param_count_in
            .contains(&u32::try_from(decl.params.len()).unwrap_or(u32::MAX))
    {
        return false;
    }
    if !target.in_owner_base.is_empty() {
        let Some(owner) = decl
            .parent
            .and_then(|symbol| local_decl_by_symbol(file_index, symbol))
        else {
            return false;
        };
        if !owner.bases.iter().any(|base| {
            target
                .in_owner_base
                .iter()
                .any(|want| semantic_owner_names_match(base, want))
        }) {
            return false;
        }
    }
    if target.in_class.is_empty() && target.in_class_suffix.is_empty() {
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
    target
        .in_class
        .iter()
        .any(|want| semantic_owner_names_match(&enclosing_class.name, want))
        || enclosing_class.bases.iter().any(|base| {
            target
                .in_class
                .iter()
                .any(|want| semantic_owner_names_match(base, want))
        })
        || target
            .in_class_suffix
            .iter()
            .any(|suffix| enclosing_class.name.ends_with(suffix))
        || enclosing_class
            .bases
            .iter()
            .any(|base| target.in_class_suffix.iter().any(|suffix| base.ends_with(suffix)))
}

fn param_target_is_context_only(target: &RuleTarget) -> bool {
    target.name.is_none()
        && target.attribute.is_none()
        && target.regex.is_none()
        && target.annotation.is_none()
        && target.default_call.is_none()
}

fn semantic_type_names_match(actual: &str, expected: &str) -> bool {
    actual == expected
        || bonsai_common::short_qualified_tail(actual) == bonsai_common::short_qualified_tail(expected)
}

/// Match a rule-authored declaration owner/base identity.
///
/// A concise expected type may match an adapter-emitted qualified owner tail,
/// but a qualified expected identity must match every compiler segment. This
/// prevents unrelated providers with a common base tail (for example two
/// distinct `Worker` modules) from satisfying each other's boundary rules.
fn semantic_owner_names_match(actual: &str, expected: &str) -> bool {
    let expected_segments = bonsai_common::qualified_name_segments(expected);
    if expected_segments.len() > 1 {
        bonsai_common::qualified_name_segments(actual) == expected_segments
    } else {
        semantic_type_names_match(actual, expected)
    }
}

fn exact_semantic_type_names_match(actual: &str, expected: &str) -> bool {
    actual.trim().trim_start_matches("::") == expected.trim().trim_start_matches("::")
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

/// Compiler-proven places whose receiver type can change when rulepack or
/// first-party call-result typing is enabled for this file.
///
/// This is a demand index only. It never assigns a type: the selected
/// declarations still run the complete uncapped fixed point below. Calls on
/// ordinary locals/fields that have no call assignment, callback origin, or
/// imported binding cannot gain a derived receiver type and therefore do not
/// force unrelated declaration work.
struct DerivedReceiverCandidates {
    by_decl: AHashMap<Span, AHashSet<String>>,
    module_places: AHashSet<String>,
    callback_arguments: Vec<bonsai_lang_api::types::CompilerCallbackArgumentHeader>,
    typed_callback_names: AHashSet<String>,
    imported_bindings: AHashSet<String>,
}

impl DerivedReceiverCandidates {
    fn from_context(ctx: &FileScanContext<'_, '_>, factory: &RulepackTyping) -> Self {
        let syntax = CompilerSyntaxHeader::from_decl_index(ctx.file_index);
        let module_span = ctx
            .file_index
            .defs
            .iter()
            .find(|decl| decl.name == bonsai_lang_api::MODULE_DECL_NAME || decl.kind == DeclKind::Module)
            .map(|decl| decl.span);
        let mut by_decl: AHashMap<Span, AHashSet<String>> = AHashMap::new();
        for assignment in &syntax.factory_assignments {
            by_decl
                .entry(assignment.owner_span)
                .or_default()
                .insert(normalize_leading_call_punctuation(&assignment.target).to_string());
        }
        loop {
            let mut changed = false;
            for alias in &syntax.assignment_aliases {
                let source = normalize_leading_call_punctuation(&alias.source);
                let target = normalize_leading_call_punctuation(&alias.target);
                let places = by_decl.entry(alias.owner_span).or_default();
                if places.contains(source) && places.insert(target.to_string()) {
                    changed = true;
                }
            }
            if !changed {
                break;
            }
        }
        let module_places = module_span
            .and_then(|span| by_decl.get(&span).cloned())
            .unwrap_or_default();
        let mut callback_arguments = syntax.callback_arguments;
        let mut typed_callback_names: AHashSet<String> = syntax
            .typed_callables
            .iter()
            .map(|callback| callback.name.clone())
            .collect();
        let mut imported_bindings = AHashSet::new();
        if let Some(imports) = ctx.file_imports {
            for binding in bonsai_lang_api::alias_map_from_imports(imports).keys() {
                imported_bindings.insert(normalize_leading_call_punctuation(binding).to_string());
            }
        }
        let has_callback_typing = ctx
            .ws
            .db()
            .adapter_for(ctx.file)
            .and_then(|adapter| factory.callback_specs_for(adapter.language_id().as_str()))
            .is_some_and(|specs| !specs.is_empty());
        if !has_callback_typing {
            callback_arguments.clear();
            typed_callback_names.clear();
        }
        Self {
            by_decl,
            module_places,
            callback_arguments,
            typed_callback_names,
            imported_bindings,
        }
    }

    fn call_can_gain_type(&self, decl: &Decl, call: &CallFact) -> bool {
        let Some(receiver) = call
            .receiver
            .as_deref()
            .or_else(|| call_receiver_text(&call.callee))
        else {
            return false;
        };
        self.place_can_gain_type(decl, receiver, call.span)
    }

    fn place_can_gain_type(&self, decl: &Decl, receiver: &str, span: Span) -> bool {
        if receiver.contains(['(', ')']) {
            return true;
        }
        let receiver = normalize_leading_call_punctuation(receiver);
        let base = match_base_name(receiver)
            .map(normalize_leading_call_punctuation)
            .unwrap_or(receiver);
        let matches_place = |places: &AHashSet<String>| places.contains(receiver) || places.contains(base);
        if self.by_decl.get(&decl.span).is_some_and(matches_place)
            || matches_place(&self.module_places)
            || self.imported_bindings.contains(receiver)
            || self.imported_bindings.contains(base)
        {
            return true;
        }
        let receiver_is_decl_param = decl.params.iter().any(|param| {
            let param = normalize_leading_call_punctuation(param);
            param == receiver || param == base
        });
        if self.typed_callback_names.contains(&decl.name) && receiver_is_decl_param {
            return true;
        }
        // Some adapters deliberately flatten inline callback bodies into the
        // enclosing declaration while retaining the exact callback span and
        // parameter list in the compiler syntax header. Other adapters emit
        // the callback as its own declaration whose span is exactly the
        // compiler callback span. Select either exact ownership form when
        // this call is inside the callback and reads one of its parameters.
        // Requiring both span containment and parameter identity prevents a
        // sibling lambda from lending its external type.
        self.callback_arguments.iter().any(|callback| {
            (decl.span == callback.callback_span
                || matcher_span_contains(decl.body_span.unwrap_or(decl.span), callback.callback_span))
                && matcher_span_contains(callback.callback_span, span)
                && callback.params.iter().any(|param| {
                    let param = normalize_leading_call_punctuation(param);
                    param == receiver || param == base
                })
        })
    }
}

/// Decide whether adapter-declared receiver facts already make call-result
/// typing irrelevant for this file's surviving endpoint rules.
///
/// This is a semantic staging decision, not a heuristic: the expensive
/// factory/first-party fixed point is skipped only when every receiver-
/// sensitive rule/call pair already has the same final verdict from direct
/// compiler types. Any untyped, negatively constrained, factory-shaped, or
/// otherwise ambiguous pair requests the complete derived projection.
fn call_batch_derived_receiver_decls<P: PackageEvidence + ?Sized>(
    ctx: &FileScanContext<'_, '_>,
    rules: &PreparedRuleBatch<'_, '_>,
    bundle: &FileDeclFactsBundle,
    file_packages: &P,
) -> Arc<[Span]> {
    let mut derived_decls = Vec::new();
    let candidates = DerivedReceiverCandidates::from_context(ctx, &rules.factory);
    for decl in &ctx.file_index.defs {
        let Some(facts) = bundle.by_decl_span.get(&decl.span) else {
            continue;
        };
        let mut needs_derived_facts = false;
        for call in &facts.calls {
            let call_can_gain_type = candidates.call_can_gain_type(decl, call);
            let mut candidate_rules = Vec::new();
            push_call_candidate_rules(&mut candidate_rules, rules, &call.callee, &facts.alias_map);
            let receiver_types = expanded_receiver_types(&call.receiver_types, ctx.receiver_base_map);
            for prepared in candidate_rules {
                if !prepared_rule_needs_call_result_types(prepared)
                    || !prepared.call_kind_allows(call.call_kind)
                    || !decl_target_context_allows(
                        ctx.file_index,
                        Some(decl),
                        prepared.rule.match_spec.callee.as_ref(),
                        None,
                    )
                {
                    continue;
                }
                if rule_primary_target(prepared.rule).is_some_and(|target| target.binding_origin.is_some()) {
                    needs_derived_facts = true;
                    break;
                }
                let Some(matched_callee) =
                    prepared.call_target_matches(call, &receiver_types, &facts.alias_map)
                else {
                    // A rule-indexed call whose target does not match direct
                    // receiver facts may become exact after factory/callback
                    // return typing. Fail toward the full fixed point.
                    if call_can_gain_type {
                        needs_derived_facts = true;
                        break;
                    }
                    continue;
                };
                if !prepared.base_name_allows(&matched_callee) {
                    continue;
                }
                if external_receiver_type_is_workspace_shadow_at(
                    prepared,
                    &receiver_types,
                    &ctx.file_index.defs,
                    ctx.file_imports,
                    Some(&matched_callee),
                ) {
                    // An already-proven lexical shadow remains a shadow when
                    // more receiver aliases are added.
                    continue;
                }
                if !base_receiver_type_allows(prepared, Some(decl), &matched_callee, &receiver_types, &[])
                    || !prepared.call_context_allows(
                        &call.callee,
                        &receiver_types,
                        &facts.alias_map,
                        file_packages,
                    )
                {
                    if call_can_gain_type {
                        needs_derived_facts = true;
                        break;
                    }
                    continue;
                }

                let mut permanently_rejected = false;
                for constraint in prepared.rule.constraints.iter() {
                    match constraint {
                        ConstraintKind::ReceiverTypeIn { receiver_type_in }
                            if !receiver_type_matches_any(&receiver_types, receiver_type_in) =>
                        {
                            if call_can_gain_type {
                                needs_derived_facts = true;
                                break;
                            }
                        }
                        ConstraintKind::ReceiverTypeNotIn { receiver_type_not_in }
                            if receiver_type_matches_any(&receiver_types, receiver_type_not_in) =>
                        {
                            permanently_rejected = true;
                            break;
                        }
                        ConstraintKind::ReceiverTypeNotIn { .. } => {
                            // A derived safe/blocked type can turn a direct
                            // positive into a rejection, so retain the full
                            // projection for negative receiver constraints.
                            if call_can_gain_type {
                                needs_derived_facts = true;
                                break;
                            }
                        }
                        _ => {}
                    }
                }
                if permanently_rejected {
                    continue;
                }
                // The rule already has an exact direct receiver verdict at
                // this site. Adding more aliases cannot create a second row
                // for the same rule/span.
            }
            if needs_derived_facts {
                break;
            }
        }
        if needs_derived_facts {
            derived_decls.push(decl.span);
        }
    }
    derived_decls.sort_unstable();
    derived_decls.dedup();
    Arc::from(derived_decls)
}

fn scan_calls_batch(
    ctx: &FileScanContext<'_, '_>,
    rules: &PreparedRuleBatch<'_, '_>,
    out: &mut Vec<RuleMatch>,
) {
    let call_setup_started = ctx.debug_timings.map(|_| Instant::now());
    let ws = ctx.ws;
    let file = ctx.file;
    let file_index = ctx.file_index;
    let mode = ctx.mode;
    let taint_view = ctx.taint_view;
    let retention = ctx.retention;
    let receiver_base_map = ctx.receiver_base_map;
    let file_packages = ctx.package_evidence;
    let import_aliases = file_alias_map_with_compiler_imports(ws, file, retention, ctx.file_imports);
    if let (Some(started), Some(timings)) = (call_setup_started, ctx.debug_timings) {
        record_elapsed_ns(&timings.call_setup, started);
    }
    let decl_facts_started = ctx.debug_timings.map(|_| Instant::now());
    let requirements = DeclFactRequirements::for_rules(rules.call_rules.iter().copied());
    let base_requirements = requirements.without(DeclFactRequirements::CALL_RESULT_TYPES);
    let base_bundle = decl_match_facts_for_retention(
        ws,
        file,
        Some(file_index),
        DeclMatchFactsRequest {
            factory: &rules.factory,
            requirements: base_requirements,
            retention,
            compiler_imports: ctx.file_imports,
            global_headers: ctx.global_headers,
            call_result_type_decls: None,
        },
    );
    let derived_receiver_decls = if requirements.contains(DeclFactRequirements::CALL_RESULT_TYPES) {
        call_batch_derived_receiver_decls(ctx, rules, base_bundle.as_ref(), file_packages)
    } else {
        Arc::<[Span]>::from([])
    };
    let bundle = if !derived_receiver_decls.is_empty() {
        if let Some(timings) = ctx.debug_timings {
            timings.derived_receiver_files.fetch_add(1, Ordering::Relaxed);
            timings
                .derived_receiver_decls
                .fetch_add(derived_receiver_decls.len(), Ordering::Relaxed);
        }
        decl_match_facts_for_retention(
            ws,
            file,
            Some(file_index),
            DeclMatchFactsRequest {
                factory: &rules.factory,
                requirements,
                retention,
                compiler_imports: ctx.file_imports,
                global_headers: ctx.global_headers,
                call_result_type_decls: Some(derived_receiver_decls),
            },
        )
    } else {
        if requirements.contains(DeclFactRequirements::CALL_RESULT_TYPES) {
            if let Some(timings) = ctx.debug_timings {
                timings.direct_receiver_files.fetch_add(1, Ordering::Relaxed);
            }
        }
        base_bundle
    };
    if let (Some(started), Some(timings)) = (decl_facts_started, ctx.debug_timings) {
        record_elapsed_ns(&timings.decl_facts, started);
    }
    let call_match_started = ctx.debug_timings.map(|_| Instant::now());
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
                let Some(matched_callee) =
                    prepared.call_target_matches(call, &receiver_types, &facts.alias_map)
                else {
                    continue;
                };
                if external_receiver_type_is_workspace_shadow_at(
                    prepared,
                    &receiver_types,
                    &file_index.defs,
                    ctx.file_imports,
                    Some(&matched_callee),
                ) {
                    continue;
                }
                if !prepared.base_name_allows(&matched_callee) {
                    continue;
                }
                if !base_receiver_type_allows(
                    prepared,
                    Some(decl),
                    &matched_callee,
                    &receiver_types,
                    &facts.derived_type_aliases,
                ) {
                    continue;
                }
                if !prepared.call_or_source_context_allows(
                    &call.callee,
                    &receiver_types,
                    &facts.alias_map,
                    file_packages,
                    file_index,
                    Some(decl),
                ) {
                    continue;
                }
                let receiver_call_count = receiver_method_key(&call.callee)
                    .and_then(|key| facts.receiver_counts.get(&key).copied());
                if !constraints_pass(ConstraintEval {
                    rule_id: &prepared.rule.id,
                    callee: &matched_callee,
                    receiver: call.receiver.as_deref(),
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
                        string_compositions: &file_index.string_compositions,
                        factory_import_identity: Some(FactoryImportIdentityContext {
                            required_imports: &prepared.rule.imports,
                            alias_map: &facts.alias_map,
                            compiler_imports: ctx.file_imports,
                            workspace: ctx.global_headers.map(|global| (ws, global)),
                        }),
                    }),
                }) {
                    continue;
                }
                let workspace_context = ctx.global_headers.map(|global| WorkspaceCallIdentityContext {
                    ws,
                    global,
                    caller: decl,
                });
                if prepared_call_binding_origin_is_invalid(
                    prepared,
                    ctx.ws
                        .db()
                        .adapter_for(decl.name_span.file)
                        .is_some_and(|adapter| adapter.capabilities().bare_call_constructor_syntax),
                    decl,
                    Some(&file_index.defs),
                    workspace_context.as_ref(),
                    call,
                    &facts.alias_map,
                    ctx.file_imports,
                ) {
                    continue;
                }
                if prepared.rule.match_spec.kind == MatchKind::New
                    && !call_has_new_identity(
                        workspace_context.as_ref(),
                        &rules.factory,
                        &prepared.rule.language,
                        call,
                        &facts.alias_map,
                        ctx.file_imports,
                    )
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

    let enclosing_callables =
        bonsai_workspace::enclosing_index::EnclosingSpanIndex::from_callable_decls(&file_index.defs);
    for r in &file_index.refs {
        if r.kind != RefKind::Call || decl_call_keys.contains(&(r.name.clone(), r.span.start)) {
            continue;
        }
        let enclosing_fn = enclosing_callables
            .enclosing(r.span.start)
            .map(|entry| entry.name);
        let mut candidate_rules = Vec::new();
        push_call_candidate_rules(&mut candidate_rules, rules, &r.name, &import_aliases);
        for prepared in candidate_rules {
            if prepared.rule.match_spec.kind == MatchKind::New {
                // A raw reference fallback has neither adapter call-kind nor
                // argument/receiver flow facts. All supported frontends lower
                // actual invocations as `FlowEvent::Call`; fail closed here
                // instead of turning a same-spelled reference into a guessed
                // constructor.
                continue;
            }
            if rule_primary_target(prepared.rule).is_some_and(|target| target.binding_origin.is_some()) {
                // A reference fallback has no adapter-lowered receiver or
                // caller binding identity. Exact external/global targets
                // must be decided from a real Call fact.
                continue;
            }
            if !prepared.call_kind_in.is_empty() {
                // Ref fallbacks do not carry the adapter-lowered call kind;
                // fail closed rather than guessing a typed operation.
                continue;
            }
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
            if !prepared.call_context_allows(&r.name, &[], &import_aliases, file_packages) {
                continue;
            }
            if !constraints_pass(ConstraintEval {
                rule_id: &prepared.rule.id,
                callee: &matched_callee,
                receiver: None,
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
    if let (Some(started), Some(timings)) = (call_match_started, ctx.debug_timings) {
        record_elapsed_ns(&timings.call_match, started);
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

/// Select read-shaped rule candidates by the exact terminal identities that
/// the compiler emitted for one structured reference/value read. This is the
/// same lossless index used for call-shaped rules: regexes without a provable
/// literal terminal remain in the wildcard bucket, and every candidate still
/// passes through the canonical target, receiver, package, binding, and
/// workspace-shadow checks in the scanners below.
fn push_read_candidate_rules<'batch, 'p, 'rule>(
    out: &mut Vec<&'p PreparedRule<'rule>>,
    rules: &'batch PreparedRuleBatch<'p, 'rule>,
    read: &str,
    alias_map: &std::collections::HashMap<String, AliasTarget>,
) {
    for &rule in &rules.read_wildcard_rules {
        push_unique_prepared_rule(out, rule);
    }
    for key in call_candidate_keys(read, alias_map) {
        if let Some(bucket) = rules.read_keyed_rules.get(&key) {
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

/// Expand the longest compiler alias prefix in a callee while preserving its
/// remaining member path. Exact module-member values may themselves carry a
/// compiler type (`module.shared_client -> Client`), so considering only the
/// first segment loses receiver identity after a namespace import. Longest
/// prefix also prevents a broader namespace alias from overriding a more
/// specific compiler binding.
fn expand_callee_alias(
    callee: &str,
    alias_map: &std::collections::HashMap<String, AliasTarget>,
) -> Option<String> {
    let segments = bonsai_common::qualified_name_segments(callee);
    if segments.is_empty() {
        return None;
    }
    let normalized = segments
        .iter()
        .enumerate()
        .map(|(index, segment)| {
            if index == 0 {
                normalize_leading_call_punctuation(segment).to_string()
            } else {
                (*segment).to_string()
            }
        })
        .collect::<Vec<_>>();
    let (prefix_len, target) = (1..=normalized.len()).rev().find_map(|prefix_len| {
        let prefix = normalized[..prefix_len].join(".");
        alias_map.get(&prefix).map(|target| (prefix_len, target))
    })?;
    let tail = normalized[prefix_len..].join(".");
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

fn read_receiver_derivation_needed(prepared: &PreparedRule<'_>, direct_types: &[String]) -> bool {
    let target_needs_type = rule_primary_target(prepared.rule).is_some_and(|target| {
        !target.receiver_type_in.is_empty()
            && !receiver_type_matches_any(direct_types, &target.receiver_type_in)
    });
    target_needs_type
        || prepared
            .rule
            .constraints
            .iter()
            .any(|constraint| match constraint {
                ConstraintKind::ReceiverTypeIn { receiver_type_in } => {
                    !receiver_type_matches_any(direct_types, receiver_type_in)
                }
                // A newly derived blocked/safe type can reverse a direct positive
                // verdict, so negative type constraints must retain derivation.
                ConstraintKind::ReceiverTypeNotIn { .. } => true,
                _ => false,
            })
}

fn read_receiver_constraints_allow(prepared: &PreparedRule<'_>, receiver_types: &[String]) -> bool {
    prepared
        .rule
        .constraints
        .iter()
        .all(|constraint| match constraint {
            ConstraintKind::ReceiverTypeIn { receiver_type_in } => {
                receiver_type_matches_any(receiver_types, receiver_type_in)
            }
            ConstraintKind::ReceiverTypeNotIn { receiver_type_not_in } => {
                !receiver_type_matches_any(receiver_types, receiver_type_not_in)
            }
            _ => true,
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

/// Fire each Missing rule on every function-shaped decl in `file` where the
/// expected callee is absent from that declaration's exact compiler facts.
/// Interprocedural absence cannot be proven by a bounded graph prefix, so
/// Missing rules deliberately remain intraprocedural.
fn scan_missing_batch(
    ctx: &FileScanContext<'_, '_>,
    rules: &[&PreparedRule<'_>],
    _include_workspace_package_context: bool,
    out: &mut Vec<RuleMatch>,
) {
    let ws = ctx.ws;
    let file = ctx.file;
    let file_index = ctx.file_index;
    let mode = ctx.mode;
    let taint_view = ctx.taint_view;
    let retention = ctx.retention;
    let file_packages = ctx.package_evidence;
    // Missing-call rules don't use factory-return typing.
    let empty_factory = empty_rulepack_typing();
    let requirements = DeclFactRequirements::for_rules(rules.iter().copied());
    let bundle = decl_match_facts_for_retention(
        ws,
        file,
        Some(file_index),
        DeclMatchFactsRequest {
            factory: empty_factory.as_ref(),
            requirements,
            retention,
            compiler_imports: ctx.file_imports,
            global_headers: None,
            call_result_type_decls: None,
        },
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
                receiver: None,
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
                    string_compositions: &file_index.string_compositions,
                    factory_import_identity: None,
                }),
            }) {
                continue;
            }

            // Does any exact call inside this declaration match the expected
            // target? A finite resolved-call walk cannot prove whole-program
            // absence and is therefore not part of the rule language.
            let target_present = facts.calls.iter().any(|call| {
                prepared
                    .call_target_matches(call, &call.receiver_types, &facts.alias_map)
                    .is_some()
                    && prepared.call_context_allows(
                        &call.callee,
                        &call.receiver_types,
                        &facts.alias_map,
                        file_packages,
                    )
            });
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

fn matching_call_has_arg_index(
    ws: &Workspace,
    file: FileId,
    file_index: &DeclIndex,
    prepared: &PreparedRule<'_>,
    global: &GlobalIndex,
    factory: &RulepackTyping,
    wanted_index: usize,
) -> bool {
    let file_packages = file_package_set_with_workspace_context_and_retention(
        ws,
        file,
        prepared.needs_workspace_package_context(),
        FactRetention::Transient,
    );
    let import_aliases = file_alias_map_with_retention(ws, file, FactRetention::Transient);
    let compiler_imports = ws.db().compiler_import_index_uncached(file);
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
            if prepared
                .call_target_matches(&call, &call.receiver_types, &alias_map)
                .is_none()
            {
                continue;
            }
            if external_receiver_type_is_workspace_shadow_at(
                prepared,
                &call.receiver_types,
                &file_index.defs,
                compiler_imports.as_ref(),
                Some(&call.callee),
            ) {
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
            let workspace_context = WorkspaceCallIdentityContext {
                ws,
                global,
                caller: decl,
            };
            if prepared_call_binding_origin_is_invalid(
                prepared,
                ws.db()
                    .adapter_for(decl.name_span.file)
                    .is_some_and(|adapter| adapter.capabilities().bare_call_constructor_syntax),
                decl,
                Some(&file_index.defs),
                Some(&workspace_context),
                &call,
                &alias_map,
                compiler_imports.as_ref(),
            ) {
                continue;
            }
            if prepared.rule.match_spec.kind == MatchKind::New
                && !call_has_new_identity(
                    Some(&workspace_context),
                    factory,
                    &prepared.rule.language,
                    &call,
                    &alias_map,
                    compiler_imports.as_ref(),
                )
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
type FilePackageSetKey = (u64, FileId, u64, u64, bool);
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

/// Borrow-friendly package evidence used only by the staged header planner.
/// Common component/manifest sets stay shared; only the usually-small exact
/// import projection for this file is owned. This is semantically equivalent
/// to the marker-prefixed union used by full matching while avoiding a
/// workspace-sized allocation for every raw-anchor candidate.
struct FilePackagePlanningEvidence {
    direct_file_packages: AHashSet<String>,
    component_packages: Arc<WorkspaceImportPackageContext>,
    manifest_packages: Option<crate::deps::WorkspaceDependencyPackages>,
    is_template: bool,
}

impl PackageEvidence for FilePackagePlanningEvidence {
    fn contains_import(
        &self,
        signal: &str,
        scope: PackageEvidenceScope,
        semantics: &crate::loader::PackageMatchSemantics,
    ) -> bool {
        let packages = match scope {
            PackageEvidenceScope::Direct => Some(&self.direct_file_packages),
            PackageEvidenceScope::Component => Some(&self.component_packages.packages),
            PackageEvidenceScope::Manifest if !self.is_template => self
                .manifest_packages
                .as_ref()
                .map(|packages| packages.packages.as_ref()),
            PackageEvidenceScope::TemplateManifest if self.is_template => self
                .manifest_packages
                .as_ref()
                .map(|packages| packages.packages.as_ref()),
            PackageEvidenceScope::Manifest | PackageEvidenceScope::TemplateManifest => None,
        };
        packages.is_some_and(|packages| {
            packages
                .iter()
                .filter(|candidate| {
                    scope != PackageEvidenceScope::Direct || !is_package_evidence_marker(candidate)
                })
                .any(|candidate| crate::pkg::import_matches_package(candidate, signal, semantics))
        })
    }

    fn local_import_allows(&self, candidate: &str, signal: &str) -> bool {
        self.direct_file_packages
            .contains(&local_import_package_marker(candidate, signal))
            || call_head(candidate).is_some_and(|head| {
                self.direct_file_packages
                    .contains(&local_import_package_marker(head, signal))
            })
    }

    fn has_local_import_package(&self, signal: &str) -> bool {
        self.direct_file_packages
            .contains(&local_import_package_signal_marker(signal))
    }
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

fn file_package_planning_evidence(
    ws: &Workspace,
    file: FileId,
    include_workspace_context: bool,
    retention: FactRetention,
    prewarmed_import_contexts: Option<&Arc<LanguageImportPackageContexts>>,
    compiler_imports: Option<&bonsai_lang_api::ImportIndex>,
) -> FilePackagePlanningEvidence {
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
    let mut direct_file_packages = AHashSet::new();
    let loaded_imports;
    let imports = if let Some(imports) = compiler_imports.or(prewarmed_file_imports) {
        Some(imports)
    } else {
        loaded_imports = match retention {
            FactRetention::Cached => ws.db().import_index(file).map(|imports| (*imports).clone()),
            FactRetention::Transient => transient_import_index(ws, file),
        };
        loaded_imports.as_ref()
    };
    if let Some(imports) = imports {
        insert_file_import_packages(
            ws,
            file,
            imports,
            retention,
            prewarmed_import_contexts.map(|contexts| &contexts.imports_by_file),
            &mut direct_file_packages,
        );
    }
    let component_packages = language_imports
        .by_file
        .get(&file)
        .map_or_else(|| Arc::new(WorkspaceImportPackageContext::default()), Arc::clone);
    let manifest_packages = (include_workspace_context
        && workspace_manifest_package_context_allowed(ws, file))
    .then(|| {
        let root = ws.db().workspace_root()?;
        let language = ws
            .db()
            .adapter_for(file)
            .map(|adapter| adapter.language_id().as_str())
            .unwrap_or("");
        Some(
            crate::deps::workspace_dependency_packages_for_language_in_workspace(
                &root,
                language,
                ws.db().vfs().instance_id(),
            ),
        )
    })
    .flatten();
    FilePackagePlanningEvidence {
        direct_file_packages,
        component_packages,
        manifest_packages,
        is_template: workspace_manifest_template_context_allowed(ws, file),
    }
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
    // `Vfs::instance_id` separates workspace lifetimes and each write/edit
    // monotonically increments this file's version. Hashing the complete
    // source again here duplicated the raw-anchor pass on every broad scan;
    // the identity tuple is already exact for this process-local cache.
    let version = ws
        .db()
        .vfs()
        .snapshot(file)
        .map_or(0, |snapshot| snapshot.version);
    let key = (
        ws.db().vfs().instance_id(),
        file,
        version,
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
        let marker = if workspace_manifest_template_context_allowed(ws, file) {
            template_manifest_package_marker
        } else {
            manifest_package_marker
        };
        out.extend(workspace_packages.packages.iter().map(|package| marker(package)));
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
        FactRetention::Transient => {
            // Header decoding is independent per immutable compiler object.
            // Keep one continuous CPU worklist while source-weighted permits
            // bound simultaneous decompression. The resulting import indexes
            // are collected in canonical FileId order below; concurrency can
            // change latency only, never the component graph or package set.
            use rayon::prelude::*;
            let memory_permits = bonsai_common::SyntaxMemoryPermitPool::for_current_process();
            files
                .par_iter()
                .filter_map(|candidate_file| {
                    let source_bytes = ws
                        .db()
                        .vfs()
                        .snapshot(*candidate_file)
                        .map_or(0, |snapshot| snapshot.text.len() as u64);
                    let _memory_permit = memory_permits.acquire(source_bytes);
                    ws.db()
                        .import_index_uncached(*candidate_file)
                        .map(|imports| (*candidate_file, imports))
                })
                .collect::<Vec<_>>()
                .into_iter()
                .collect()
        }
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
                .wrapping_add(snapshot.version);
            let fingerprint = component_fingerprints.entry(root).or_default();
            *fingerprint = fingerprint
                .wrapping_mul(16_777_619)
                .wrapping_add(u64::from(candidate_file.raw()))
                .wrapping_add(snapshot.version);
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
    out.insert(local_import_package_signal_marker(package));
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
    let importer_path = ws.vfs().path(importer).ok()?;
    let adapter = ws.db().adapter_for(importer)?;
    import_candidate_paths(&importer_path, module, &adapter.capabilities())
        .into_iter()
        .find_map(|candidate| ws.vfs().lookup(&candidate))
}

/// Adapter-owned module-path policy shared by source matching and code
/// manifests. These are lookup candidates, not proof of a resolved callable.
pub(crate) fn import_candidate_paths(
    importer_path: &std::path::Path,
    module: &str,
    capabilities: &bonsai_lang_api::LanguageCapabilities,
) -> Vec<std::path::PathBuf> {
    let Some(base_dir) = importer_path.parent() else {
        return Vec::new();
    };
    if !module.starts_with('.') && !capabilities.unqualified_imports_search_current_directory {
        return Vec::new();
    }
    let module_path = if module.starts_with('.') {
        module.to_string()
    } else {
        module.replace('.', std::path::MAIN_SEPARATOR_STR)
    };
    let raw = normalize_path(&base_dir.join(module_path));
    let extensions = capabilities.module_resolution_extensions;
    relative_import_candidates(&raw, extensions)
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
    let extension = std::path::Path::new(path.as_ref())
        .extension()
        .and_then(|ext| ext.to_str());
    extension.is_some_and(|ext| {
        adapter
            .file_extensions()
            .iter()
            .any(|source_ext| source_ext.eq_ignore_ascii_case(ext))
            || extensions
                .iter()
                .any(|template_ext| template_ext.eq_ignore_ascii_case(ext))
    })
}

fn workspace_manifest_template_context_allowed(ws: &Workspace, file: FileId) -> bool {
    let Some(adapter) = ws.db().adapter_for(file) else {
        return false;
    };
    let Ok(path) = ws.vfs().path(file) else {
        return false;
    };
    let extension = path.extension().and_then(|ext| ext.to_str());
    extension.is_some_and(|ext| {
        adapter
            .capabilities()
            .workspace_manifest_context_extensions
            .iter()
            .any(|template_ext| template_ext.eq_ignore_ascii_case(ext))
    })
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
    /// `local → ReturnType` aliases synthesized from exact first-party
    /// call resolution plus rulepack-declared external call results
    /// (`returns_type`) and structured constructors (`kind: new`). Consulted
    /// by `base_receiver_type_allows` so receiver-typed rules resolve without
    /// local-variable spelling guesses.
    derived_type_aliases: Vec<TypeAliasBinding>,
}

/// Exact derived-fact projection required by one prepared rule batch.
///
/// The compiler object remains complete. This mask only prevents the matcher
/// from repeatedly deriving unrelated secondary views (decorators, must-alias
/// closure, lifecycle state, and similar facts) for a file whose surviving
/// rules cannot consult them. It is part of the cache identity, so a later
/// rule batch that needs more evidence always builds the larger exact view.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
struct DeclFactRequirements(u8);

impl DeclFactRequirements {
    const ASSIGNMENT_TEXTS: u8 = 1 << 0;
    const RECEIVER_COUNTS: u8 = 1 << 1;
    const DECORATORS: u8 = 1 << 2;
    const ALIAS_CHAINS: u8 = 1 << 3;
    const RUNTIME_TYPES: u8 = 1 << 4;
    const LIFECYCLE: u8 = 1 << 5;
    const CALL_RESULT_TYPES: u8 = 1 << 6;

    fn insert(&mut self, flag: u8) {
        self.0 |= flag;
    }

    fn contains(self, flag: u8) -> bool {
        self.0 & flag != 0
    }

    fn without(mut self, flag: u8) -> Self {
        self.0 &= !flag;
        self
    }

    fn for_rules<'p, 'rule: 'p>(rules: impl IntoIterator<Item = &'p PreparedRule<'rule>>) -> Self {
        let mut requirements = Self::default();
        for prepared in rules {
            if prepared_rule_needs_call_result_types(prepared) {
                requirements.insert(Self::CALL_RESULT_TYPES);
            }
            for constraint in prepared.rule.constraints.iter() {
                match constraint {
                    ConstraintKind::ArgMatchesRegex { .. }
                    | ConstraintKind::ArgNotMatchesRegex { .. }
                    | ConstraintKind::AnyArgMatchesRegex { .. } => {
                        requirements.insert(Self::ASSIGNMENT_TEXTS);
                    }
                    ConstraintKind::SameReceiverCallCountAtLeast { .. } => {
                        requirements.insert(Self::RECEIVER_COUNTS);
                    }
                    ConstraintKind::EnclosingDecoratorIn { .. }
                    | ConstraintKind::EnclosingDecoratorNotIn { .. } => {
                        requirements.insert(Self::DECORATORS);
                    }
                    ConstraintKind::MustAlias { .. } => {
                        requirements.insert(Self::ALIAS_CHAINS);
                    }
                    ConstraintKind::RequiresRuntimeType { .. } => {
                        requirements.insert(Self::RUNTIME_TYPES);
                    }
                    ConstraintKind::RequiresState { .. } => {
                        requirements.insert(Self::LIFECYCLE);
                    }
                    _ => {}
                }
            }
        }
        requirements
    }
}

fn prepared_rule_needs_call_result_types(prepared: &PreparedRule<'_>) -> bool {
    let target = rule_primary_target(prepared.rule);
    matches!(
        prepared.rule.match_spec.kind,
        MatchKind::Call | MatchKind::New | MatchKind::Read | MatchKind::Write
    ) && (prepared.requires_call_package_signal
        || target.is_some_and(|target| {
            !target.receiver_type_in.is_empty()
                || target.attribute.as_ref().is_some_and(|parts| parts.len() >= 2)
        })
        || prepared.rule.constraints.iter().any(|constraint| {
            matches!(
                constraint,
                ConstraintKind::ReceiverTypeIn { .. } | ConstraintKind::ReceiverTypeNotIn { .. }
            )
        }))
}

/// Bundle of per-decl facts for one file, keyed by `decl.span` (the
/// stable identifier for a decl within a file).
#[derive(Default)]
struct FileDeclFactsBundle {
    by_decl_span: AHashMap<Span, Arc<DeclMatchFacts>>,
}

// Process-level shared cache keyed on VFS identity, file identity, content,
// and rulepack-typing policy. Earlier this was a
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
    kind: MatchKind,
    method: String,
    receiver_path: Vec<String>,
    receiver_types: Vec<String>,
    type_name: String,
    required_imports: Vec<String>,
    binding_origin: Option<RuleBindingOrigin>,
}

/// Exact constructor identity declared by a structured `kind: new` rule.
/// This is deliberately separate from return typing: identifying a call as a
/// constructor must not, by itself, inject receiver types into unrelated
/// rules. A `returns_type` declaration opts into that second capability.
#[derive(Debug, Clone)]
struct ConstructorSpec {
    method: String,
    receiver_path: Vec<String>,
    required_imports: Vec<String>,
}

/// Rulepack-owned type information for callback parameters whose source
/// syntax omits them. The compiler supplies only the callback relationship
/// (call argument or typed callable binding); provider/API identities and the
/// external signature stay in YAML.
#[derive(Debug, Clone)]
struct CallbackParamTypeSpec {
    kind: MatchKind,
    target: RuleTarget,
    callback_arg_index: Option<usize>,
    callback_field_path: Vec<String>,
    param_types: Vec<Vec<String>>,
    required_imports: Vec<String>,
    binding_origin: Option<RuleBindingOrigin>,
}

/// Rulepack-owned call-to-state transfer. The target carries the exact
/// provider/API match, while `binding` and `state` are generic lifecycle IR.
#[derive(Debug, Clone)]
struct LifecycleTransitionSpec {
    target: RuleTarget,
    binding: LifecycleBindingTarget,
    state: String,
    required_imports: Vec<String>,
}

#[derive(Debug, Default)]
pub(crate) struct RulepackTyping {
    /// language → factory return specs. Scoped by language so a Python
    /// `cursor → Cursor` rule can never type a `.cursor()` call in a
    /// JS/Ruby/etc. file. Specs with an empty receiver path preserve the
    /// original method-name-only behavior; specs from
    /// `attribute: [Receiver, method]` require the assignment RHS callee
    /// to end in that receiver path before typing the local. A
    /// `receiver_type_in` constraint instead requires an adapter/compiler
    /// type alias for the receiver, enabling exact fluent return typing
    /// without putting a library method inventory in shared code.
    by_language: AHashMap<String, Vec<FactoryReturnSpec>>,
    constructors_by_language: AHashMap<String, Vec<ConstructorSpec>>,
    callback_params_by_language: AHashMap<String, Vec<CallbackParamTypeSpec>>,
    lifecycle_by_language: AHashMap<String, Vec<LifecycleTransitionSpec>>,
    /// `0` when empty, so the declaration-facts cache key is byte-identical
    /// to a run without typing rules. The feature remains dormant unless the
    /// pack declares a compiler model.
    fingerprint: u64,
}

impl RulepackTyping {
    fn is_empty(&self) -> bool {
        self.by_language.is_empty()
            && self.constructors_by_language.is_empty()
            && self.callback_params_by_language.is_empty()
            && self.lifecycle_by_language.is_empty()
    }
    fn specs_for(&self, language: &str) -> Option<&[FactoryReturnSpec]> {
        self.by_language.get(language).map(Vec::as_slice)
    }

    fn callback_specs_for(&self, language: &str) -> Option<&[CallbackParamTypeSpec]> {
        self.callback_params_by_language.get(language).map(Vec::as_slice)
    }

    fn constructor_specs_for(&self, language: &str) -> Option<&[ConstructorSpec]> {
        self.constructors_by_language.get(language).map(Vec::as_slice)
    }

    fn lifecycle_specs_for(&self, language: &str) -> Option<&[LifecycleTransitionSpec]> {
        self.lifecycle_by_language.get(language).map(Vec::as_slice)
    }
}

static EMPTY_RULEPACK_TYPING: std::sync::LazyLock<Arc<RulepackTyping>> =
    std::sync::LazyLock::new(|| Arc::new(RulepackTyping::default()));

/// Shared empty map for the non-taint match paths (sink inventory,
/// source enumeration, tests). Cloning the `Arc` is O(1) and keeps the
/// cache key fingerprint at 0.
pub(crate) fn empty_rulepack_typing() -> Arc<RulepackTyping> {
    EMPTY_RULEPACK_TYPING.clone()
}

/// Compile rulepack-owned type models. Factory methods come from structured
/// `returns_type` rules. A structured `kind: new` rule separately supplies
/// the language/API-independent constructor identity implied by that rule.
/// This is how adapters whose CST represents constructors and functions with
/// the same call node (Kotlin, Python, Ruby, and similar grammars) retain exact
/// external-constructor behavior without a capitalization guess or an
/// engine-owned API list.
/// Callback signatures retain their exact call or declared-type selector.
/// Regex-only callees are skipped because they have no exact identity to type.
pub(crate) fn build_rulepack_typing(rules: &[&Rule]) -> Arc<RulepackTyping> {
    let mut by_language: AHashMap<String, Vec<FactoryReturnSpec>> = AHashMap::new();
    let mut constructors_by_language: AHashMap<String, Vec<ConstructorSpec>> = AHashMap::new();
    let mut callback_params_by_language: AHashMap<String, Vec<CallbackParamTypeSpec>> = AHashMap::new();
    let mut lifecycle_by_language: AHashMap<String, Vec<LifecycleTransitionSpec>> = AHashMap::new();
    for rule in rules {
        if !rule.enabled {
            continue;
        }
        if !rule.callback_param_types.is_empty() {
            if let Some(target) = rule_primary_target(rule) {
                callback_params_by_language
                    .entry(rule.language.clone())
                    .or_default()
                    .push(CallbackParamTypeSpec {
                        kind: rule.match_spec.kind,
                        target: target.clone(),
                        callback_arg_index: rule.callback_arg_index.map(|index| index as usize),
                        callback_field_path: rule.callback_field_path.clone(),
                        param_types: rule.callback_param_types.clone(),
                        required_imports: rule.imports.clone(),
                        binding_origin: target.binding_origin,
                    });
            }
        }
        if let (Some(transition), Some(target)) =
            (&rule.lifecycle_transition, rule.match_spec.callee.as_ref())
        {
            lifecycle_by_language
                .entry(rule.language.clone())
                .or_default()
                .push(LifecycleTransitionSpec {
                    target: target.clone(),
                    binding: transition.binding.clone(),
                    state: transition.state.clone(),
                    required_imports: rule.imports.clone(),
                });
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
        if rule.match_spec.kind == MatchKind::New {
            constructors_by_language
                .entry(rule.language.clone())
                .or_default()
                .push(ConstructorSpec {
                    method: method.to_string(),
                    receiver_path: receiver_path.clone(),
                    required_imports: rule.imports.clone(),
                });
        }
        if let Some(ty) = rule.returns_type.as_deref().filter(|ty| !ty.is_empty()) {
            // Receiver identity can be expressed either on the structured
            // callee target or as a standalone constraint. Both forms are
            // part of the exact rule contract; dropping the target-owned
            // types turns a rulepack return model into an untyped method-name
            // guess and also prevents direct factory chains from matching.
            let mut receiver_types = target.receiver_type_in.clone();
            receiver_types.extend(
                rule.constraints
                    .iter()
                    .filter_map(|constraint| match constraint {
                        ConstraintKind::ReceiverTypeIn { receiver_type_in } => {
                            Some(receiver_type_in.as_slice())
                        }
                        _ => None,
                    })
                    .flatten()
                    .cloned(),
            );
            receiver_types.sort();
            receiver_types.dedup();
            by_language
                .entry(rule.language.clone())
                .or_default()
                .push(FactoryReturnSpec {
                    kind: rule.match_spec.kind,
                    method: method.to_string(),
                    receiver_path,
                    receiver_types,
                    type_name: ty.to_string(),
                    required_imports: rule.imports.clone(),
                    binding_origin: target.binding_origin,
                });
        }
    }
    if by_language.is_empty()
        && constructors_by_language.is_empty()
        && callback_params_by_language.is_empty()
        && lifecycle_by_language.is_empty()
    {
        return empty_rulepack_typing();
    }
    // Deterministic, length-delimited fingerprint over sorted
    // (language, receiver, method, type) tuples so the decl-facts cache never
    // serves a bundle built for a different pack.
    let mut langs: Vec<&String> = by_language.keys().collect();
    langs.sort();
    let mut hasher = StableHasher::new();
    hasher.absorb(b"bonsai-matcher-rulepack-call-types-v4");
    hasher.absorb_separator();
    for lang in langs {
        hasher.absorb(&(lang.len() as u64).to_le_bytes());
        hasher.absorb(lang.as_bytes());
        let mut specs: Vec<&FactoryReturnSpec> = by_language[lang].iter().collect();
        specs.sort_by(|a, b| {
            (
                a.kind,
                &a.receiver_path,
                &a.receiver_types,
                &a.method,
                &a.type_name,
                &a.required_imports,
                a.binding_origin,
            )
                .cmp(&(
                    b.kind,
                    &b.receiver_path,
                    &b.receiver_types,
                    &b.method,
                    &b.type_name,
                    &b.required_imports,
                    b.binding_origin,
                ))
        });
        hasher.absorb(&(specs.len() as u64).to_le_bytes());
        for spec in specs {
            hasher.absorb(&(spec.receiver_path.len() as u64).to_le_bytes());
            for segment in &spec.receiver_path {
                hasher.absorb(&(segment.len() as u64).to_le_bytes());
                hasher.absorb(segment.as_bytes());
            }
            hasher.absorb(&(spec.receiver_types.len() as u64).to_le_bytes());
            for type_name in &spec.receiver_types {
                hasher.absorb(&(type_name.len() as u64).to_le_bytes());
                hasher.absorb(type_name.as_bytes());
            }
            hasher.absorb(&(spec.method.len() as u64).to_le_bytes());
            hasher.absorb(spec.method.as_bytes());
            hasher.absorb(&(spec.type_name.len() as u64).to_le_bytes());
            hasher.absorb(spec.type_name.as_bytes());
            let kind = serde_json::to_vec(&spec.kind).expect("match kinds are serializable");
            hasher.absorb(&(kind.len() as u64).to_le_bytes());
            hasher.absorb(&kind);
            hasher.absorb(&(spec.required_imports.len() as u64).to_le_bytes());
            for import in &spec.required_imports {
                hasher.absorb(&(import.len() as u64).to_le_bytes());
                hasher.absorb(import.as_bytes());
            }
            let binding_origin =
                serde_json::to_vec(&spec.binding_origin).expect("binding origins are serializable");
            hasher.absorb(&(binding_origin.len() as u64).to_le_bytes());
            hasher.absorb(&binding_origin);
        }
        hasher.absorb_separator();
    }
    let mut constructor_langs: Vec<&String> = constructors_by_language.keys().collect();
    constructor_langs.sort();
    hasher.absorb(b"constructor-identities-v1");
    hasher.absorb_separator();
    for lang in constructor_langs {
        hasher.absorb(&(lang.len() as u64).to_le_bytes());
        hasher.absorb(lang.as_bytes());
        let mut specs: Vec<&ConstructorSpec> = constructors_by_language[lang].iter().collect();
        specs.sort_by(|a, b| {
            (&a.receiver_path, &a.method, &a.required_imports).cmp(&(
                &b.receiver_path,
                &b.method,
                &b.required_imports,
            ))
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
            hasher.absorb(&(spec.required_imports.len() as u64).to_le_bytes());
            for import in &spec.required_imports {
                hasher.absorb(&(import.len() as u64).to_le_bytes());
                hasher.absorb(import.as_bytes());
            }
        }
        hasher.absorb_separator();
    }
    let mut callback_langs: Vec<&String> = callback_params_by_language.keys().collect();
    callback_langs.sort();
    hasher.absorb(b"callback-param-types-v2");
    hasher.absorb_separator();
    for lang in callback_langs {
        hasher.absorb(&(lang.len() as u64).to_le_bytes());
        hasher.absorb(lang.as_bytes());
        let mut encoded = callback_params_by_language[lang]
            .iter()
            .map(|spec| {
                serde_json::to_vec(&(
                    spec.kind,
                    &spec.target,
                    spec.callback_arg_index,
                    &spec.callback_field_path,
                    &spec.param_types,
                    &spec.required_imports,
                    spec.binding_origin,
                ))
            })
            .collect::<Result<Vec<_>, _>>()
            .expect("callback typing specs are serializable");
        encoded.sort();
        hasher.absorb(&(encoded.len() as u64).to_le_bytes());
        for bytes in encoded {
            hasher.absorb(&(bytes.len() as u64).to_le_bytes());
            hasher.absorb(&bytes);
        }
        hasher.absorb_separator();
    }
    let mut lifecycle_langs: Vec<&String> = lifecycle_by_language.keys().collect();
    lifecycle_langs.sort();
    hasher.absorb(b"lifecycle-transitions-v1");
    hasher.absorb_separator();
    for lang in lifecycle_langs {
        hasher.absorb(&(lang.len() as u64).to_le_bytes());
        hasher.absorb(lang.as_bytes());
        let mut encoded = lifecycle_by_language[lang]
            .iter()
            .map(|spec| {
                serde_json::to_vec(&(&spec.target, &spec.binding, &spec.state, &spec.required_imports))
            })
            .collect::<Result<Vec<_>, _>>()
            .expect("lifecycle typing specs are serializable");
        encoded.sort();
        hasher.absorb(&(encoded.len() as u64).to_le_bytes());
        for bytes in encoded {
            hasher.absorb(&(bytes.len() as u64).to_le_bytes());
            hasher.absorb(&bytes);
        }
        hasher.absorb_separator();
    }
    Arc::new(RulepackTyping {
        by_language,
        constructors_by_language,
        callback_params_by_language,
        lifecycle_by_language,
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

fn factory_spec_matches_call(
    call_name: &str,
    call_receiver: Option<&str>,
    spec: &FactoryReturnSpec,
    alias_map: &std::collections::HashMap<String, AliasTarget>,
) -> bool {
    if !callee_tail_matches(call_name, &spec.method) {
        return false;
    }
    if !spec.receiver_types.is_empty() {
        let Some(receiver) = call_receiver.or_else(|| bonsai_common::qualified_name_owner(call_name)) else {
            return false;
        };
        let receiver = normalize_leading_call_punctuation(receiver.trim());
        let typed = receiver_type_matches_wanted(receiver, &spec.receiver_types)
            || matches!(
                alias_map.get(receiver),
                Some(AliasTarget::Type { type_name })
                    if receiver_type_matches_wanted(type_name, &spec.receiver_types)
            );
        if !typed {
            return false;
        }
    }
    if !spec.receiver_path.is_empty() {
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
        if segments[start..] != spec.receiver_path {
            return false;
        }
    }
    true
}

fn constructor_spec_matches_call(
    call_name: &str,
    call_receiver: Option<&str>,
    spec: &ConstructorSpec,
) -> bool {
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

/// Return whether the rulepack explicitly identifies this call target as a
/// constructor. The proof uses only structured `kind: new` metadata plus the
/// compiler import-alias map; concrete constructor/API names remain in YAML.
fn rulepack_constructor_matches_call(
    typing: &RulepackTyping,
    language: &str,
    call_name: &str,
    call_receiver: Option<&str>,
    alias_map: &std::collections::HashMap<String, AliasTarget>,
    compiler_imports: Option<&bonsai_lang_api::ImportIndex>,
) -> bool {
    let Some(specs) = typing.constructor_specs_for(language) else {
        return false;
    };
    let expanded = expand_callee_alias(call_name, alias_map);
    specs.iter().any(|spec| {
        typing_imports_allow(&spec.required_imports, compiler_imports)
            && (constructor_spec_matches_call(call_name, call_receiver, spec)
                || expanded
                    .as_deref()
                    .is_some_and(|expanded| constructor_spec_matches_call(expanded, None, spec)))
    })
}

struct WorkspaceCallIdentityContext<'a> {
    ws: &'a Workspace,
    global: &'a GlobalIndex,
    caller: &'a Decl,
}

/// Return the compiler binding that owns a call's callable identity.
///
/// Adapters already normalize both the complete callee and the receiver. The
/// first receiver/callee path segment is therefore the lexical binding a
/// language resolver would consult; no provider spelling is interpreted
/// here. Call-expression receivers deliberately fail closed because an
/// intermediate return value is not a lexical binding.
fn identity_binding_root(identity: &str) -> Option<String> {
    let identity = identity.trim();
    let root = bonsai_common::qualified_name_segments(identity)
        .first()
        .copied()
        .map(normalize_leading_call_punctuation)
        .unwrap_or(identity)
        .trim();
    (!root.is_empty()
        && root
            .chars()
            .all(|ch| ch == '_' || ch == '$' || ch.is_ascii_alphanumeric()))
    .then(|| root.to_string())
}

fn call_identity_binding_root(call: &CallFact) -> Option<String> {
    identity_binding_root(call.receiver.as_deref().unwrap_or(&call.callee))
}

fn assignment_is_exact_import_binding(
    root: &str,
    span: Span,
    required_imports: &[String],
    compiler_imports: Option<&bonsai_lang_api::ImportIndex>,
) -> bool {
    compiler_imports.is_some_and(|imports| {
        imports.imports.iter().any(|import| {
            import.alias.as_deref() == Some(root)
                && (required_imports.is_empty()
                    || required_imports
                        .iter()
                        .any(|wanted| import_module_matches(&import.module, wanted)))
                && spans_overlap(span, import.span)
        })
    })
}

fn local_non_import_binding_shadows_import_alias(
    events: &[FlowEvent],
    root: &str,
    call_span: Span,
    required_imports: &[String],
    compiler_imports: Option<&bonsai_lang_api::ImportIndex>,
) -> bool {
    fn walk(
        events: &[FlowEvent],
        root: &str,
        call_span: Span,
        required_imports: &[String],
        compiler_imports: Option<&bonsai_lang_api::ImportIndex>,
    ) -> bool {
        events.iter().any(|event| match event {
            FlowEvent::Assign { target, span, .. } => {
                if span.end > call_span.start || normalize_leading_call_punctuation(target) != root {
                    return false;
                }
                !assignment_is_exact_import_binding(root, *span, required_imports, compiler_imports)
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                walk(then_events, root, call_span, required_imports, compiler_imports)
                    || walk(else_events, root, call_span, required_imports, compiler_imports)
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                walk(body, root, call_span, required_imports, compiler_imports)
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                walk(body, root, call_span, required_imports, compiler_imports)
                    || walk(catch_events, root, call_span, required_imports, compiler_imports)
                    || walk(
                        finally_events,
                        root,
                        call_span,
                        required_imports,
                        compiler_imports,
                    )
            }
            _ => false,
        })
    }

    walk(events, root, call_span, required_imports, compiler_imports)
}

fn flow_contains_exact_non_import_binding(
    events: &[FlowEvent],
    root: &str,
    required_imports: &[String],
    compiler_imports: Option<&bonsai_lang_api::ImportIndex>,
) -> bool {
    events.iter().any(|event| match event {
        FlowEvent::Assign { target, span, .. } => {
            normalize_leading_call_punctuation(target) == root
                && !assignment_is_exact_import_binding(root, *span, required_imports, compiler_imports)
        }
        FlowEvent::Branch {
            then_events,
            else_events,
            ..
        } => {
            flow_contains_exact_non_import_binding(then_events, root, required_imports, compiler_imports)
                || flow_contains_exact_non_import_binding(
                    else_events,
                    root,
                    required_imports,
                    compiler_imports,
                )
        }
        FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
            flow_contains_exact_non_import_binding(body, root, required_imports, compiler_imports)
        }
        FlowEvent::Try {
            body,
            catch_events,
            finally_events,
            ..
        } => {
            flow_contains_exact_non_import_binding(body, root, required_imports, compiler_imports)
                || flow_contains_exact_non_import_binding(
                    catch_events,
                    root,
                    required_imports,
                    compiler_imports,
                )
                || flow_contains_exact_non_import_binding(
                    finally_events,
                    root,
                    required_imports,
                    compiler_imports,
                )
        }
        _ => false,
    })
}

#[allow(clippy::too_many_arguments)] // Binding identity proof keeps compiler declarations, aliases, imports, and exact span visible.
fn write_binding_origin_is_valid(
    ws: &Workspace,
    file: FileId,
    origin: RuleBindingOrigin,
    caller: &Decl,
    file_decls: &[Decl],
    target: &str,
    span: Span,
    alias_map: &std::collections::HashMap<String, AliasTarget>,
    required_imports: &[String],
    compiler_imports: Option<&bonsai_lang_api::ImportIndex>,
) -> bool {
    let Some(root) = identity_binding_root(target) else {
        return false;
    };
    let synthetic = CallFact {
        callee: target.to_string(),
        receiver: None,
        span,
        args: Vec::new(),
        receiver_types: Vec::new(),
        call_kind: CallKind::Function,
        origin: CallFactOrigin::SyntheticWrite,
    };
    if !call_binding_origin_is_valid(
        origin,
        false,
        caller,
        Some(file_decls),
        None,
        &synthetic,
        alias_map,
        required_imports,
        compiler_imports,
    ) {
        return false;
    }

    // A module/file binding shadows a runtime global or imported owner for
    // every nested declaration. Compiler declarations and the synthetic
    // module body provide the scope fact; the matcher does not interpret the
    // provider spelling.
    if file_decls.iter().any(|decl| {
        if decl.symbol == caller.symbol || decl.parent.is_some() {
            return false;
        }
        if decl.name == bonsai_lang_api::kit::MODULE_DECL_NAME {
            return flow_contains_exact_non_import_binding(
                &decl.flow_events,
                &root,
                required_imports,
                compiler_imports,
            );
        }
        declaration_binds_root(decl, &root)
            && !(origin == RuleBindingOrigin::Imported && decl.kind == DeclKind::Import)
    }) {
        return false;
    }

    if origin == RuleBindingOrigin::Imported {
        let module_matches_rule = |module: &str| {
            required_imports.is_empty()
                || required_imports
                    .iter()
                    .any(|wanted| import_module_matches(module, wanted))
        };
        let mut saw_exact_import = false;
        let mut saw_workspace_local_import = false;
        if let Some(AliasTarget::Member { module, .. } | AliasTarget::Namespace { module }) =
            alias_map.get(&root)
        {
            if module_matches_rule(module) {
                saw_exact_import = true;
                saw_workspace_local_import |= resolve_relative_import_file(ws, file, module).is_some();
            }
        }
        if let Some(imports) = compiler_imports {
            for import in &imports.imports {
                let binds_root = import.alias.as_deref() == Some(root.as_str())
                    || (import.alias.is_none() && import.is_wildcard && module_matches_rule(&import.module));
                if !binds_root || !module_matches_rule(&import.module) {
                    continue;
                }
                saw_exact_import = true;
                saw_workspace_local_import |=
                    resolve_relative_import_file(ws, file, &import.module).is_some();
            }
        }
        if !saw_exact_import || saw_workspace_local_import {
            return false;
        }
    }

    true
}

#[allow(clippy::too_many_arguments)] // Prepared matcher wrapper mirrors the exact binding-origin proof inputs.
fn prepared_write_binding_origin_is_invalid(
    ws: &Workspace,
    file: FileId,
    prepared: &PreparedRule<'_>,
    caller: &Decl,
    file_decls: &[Decl],
    target: &str,
    span: Span,
    alias_map: &std::collections::HashMap<String, AliasTarget>,
    compiler_imports: Option<&bonsai_lang_api::ImportIndex>,
) -> bool {
    rule_primary_target(prepared.rule).is_some_and(|target_rule| {
        target_rule.binding_origin.is_some_and(|origin| {
            !write_binding_origin_is_valid(
                ws,
                file,
                origin,
                caller,
                file_decls,
                target,
                span,
                alias_map,
                &prepared.rule.imports,
                compiler_imports,
            )
        })
    })
}

/// Reject a read-shaped reference whose rule-declared binding origin cannot
/// be proven from compiler lexical/import facts. A missing enclosing
/// declaration is insufficient evidence and therefore fails closed.
#[allow(clippy::too_many_arguments)] // Prepared matcher wrapper mirrors the exact binding-origin proof inputs.
fn prepared_reference_binding_origin_is_invalid(
    ws: &Workspace,
    file: FileId,
    prepared: &PreparedRule<'_>,
    caller: Option<&Decl>,
    file_decls: &[Decl],
    target: &str,
    span: Span,
    alias_map: &std::collections::HashMap<String, AliasTarget>,
    compiler_imports: Option<&bonsai_lang_api::ImportIndex>,
) -> bool {
    rule_primary_target(prepared.rule).is_some_and(|target_rule| {
        target_rule.binding_origin.is_some_and(|origin| {
            caller.is_none_or(|caller| {
                !write_binding_origin_is_valid(
                    ws,
                    file,
                    origin,
                    caller,
                    file_decls,
                    target,
                    span,
                    alias_map,
                    &prepared.rule.imports,
                    compiler_imports,
                )
            })
        })
    })
}

/// Prove the rule-declared binding origin for one call using compiler facts.
/// Lexical values/functions always win. Imported targets additionally require
/// either an exact adapter-emitted import alias or an exact wildcard import of
/// a namespace declared by the rule. Runtime globals need only remain
/// lexically unshadowed.
#[allow(clippy::too_many_arguments)] // Callable identity needs declaration, type, alias, import, and call facts together.
fn call_binding_origin_is_valid(
    origin: RuleBindingOrigin,
    bare_type_is_callable: bool,
    caller: &Decl,
    file_decls: Option<&[Decl]>,
    context: Option<&WorkspaceCallIdentityContext<'_>>,
    call: &CallFact,
    alias_map: &std::collections::HashMap<String, AliasTarget>,
    required_imports: &[String],
    compiler_imports: Option<&bonsai_lang_api::ImportIndex>,
) -> bool {
    let Some(root) = call_identity_binding_root(call) else {
        return false;
    };
    if caller
        .params
        .iter()
        .any(|param| normalize_leading_call_punctuation(param) == root)
    {
        return false;
    }
    let local_value_shadow =
        bonsai_callgraph::local_value_binding_shadows_callable(&caller.flow_events, &root, call.span);
    if local_value_shadow
        && match origin {
            RuleBindingOrigin::RuntimeGlobal => true,
            RuleBindingOrigin::Imported => local_non_import_binding_shadows_import_alias(
                &caller.flow_events,
                &root,
                call.span,
                required_imports,
                compiler_imports,
            ),
        }
    {
        return false;
    }
    if file_decls.is_some_and(|decls| {
        decls.iter().any(|decl| {
            decl.name == bonsai_lang_api::kit::MODULE_DECL_NAME
                && flow_contains_exact_non_import_binding(
                    &decl.flow_events,
                    &root,
                    required_imports,
                    compiler_imports,
                )
        })
    }) {
        return false;
    }
    if file_decls.is_some_and(|decls| {
        decls.iter().any(|decl| {
            decl.symbol != caller.symbol
                && matches!(
                    decl.kind,
                    DeclKind::Module
                        | DeclKind::Namespace
                        | DeclKind::Class
                        | DeclKind::Struct
                        | DeclKind::Trait
                        | DeclKind::Interface
                        | DeclKind::Enum
                )
                && declaration_binds_root(decl, &root)
        })
    }) {
        return false;
    }
    let bare_call = bonsai_common::qualified_name_owner(&call.callee).is_none();
    if bare_call
        && file_decls.is_some_and(|decls| {
            decls.iter().any(|decl| {
                decl.name == root
                    && (matches!(
                        decl.kind,
                        DeclKind::Function | DeclKind::Method | DeclKind::Constructor
                    ) || (bare_type_is_callable
                        && matches!(decl.kind, DeclKind::Class | DeclKind::Struct | DeclKind::Enum)))
                    && (decl.parent.is_none()
                        || decl.parent == caller.parent
                        || decl.parent == Some(caller.symbol)
                        || decl
                            .parent
                            .and_then(|parent| decls.iter().find(|owner| owner.symbol == parent))
                            .is_some_and(|owner| {
                                matches!(
                                    owner.kind,
                                    DeclKind::Function | DeclKind::Method | DeclKind::Constructor
                                ) && matcher_span_contains(owner.body_span.unwrap_or(owner.span), call.span)
                            }))
            })
        })
    {
        return false;
    }
    // An exact external import alias is a file-local lexical binding. A
    // same-named declaration in another source file cannot shadow it. Keep
    // workspace resolution for runtime globals, wildcard/unproven imports,
    // and relative imports whose target is part of this workspace; those
    // identities can genuinely resolve to first-party code.
    let exact_external_import_alias = origin == RuleBindingOrigin::Imported
        && alias_map.get(&root).is_some_and(|target| {
            let module = match target {
                AliasTarget::Member { module, .. } | AliasTarget::Namespace { module } => module,
                AliasTarget::Type { .. } => return false,
            };
            context.is_none_or(|context| {
                resolve_relative_import_file(context.ws, caller.span.file, module).is_none()
            })
        });
    if bare_call
        && !exact_external_import_alias
        && context.is_some_and(|context| {
            workspace_call_resolves_as_constructor(context, &call.callee, call.span, alias_map).is_some()
        })
    {
        return false;
    }
    match origin {
        RuleBindingOrigin::RuntimeGlobal => true,
        RuleBindingOrigin::Imported => {
            matches!(
                alias_map.get(&root),
                Some(AliasTarget::Member { .. } | AliasTarget::Namespace { .. })
            ) || compiler_imports.is_some_and(|imports| {
                imports.imports.iter().any(|import| {
                    (import.is_wildcard
                        && import.alias.is_none()
                        && required_imports
                            .iter()
                            .any(|required| import_module_matches(&import.module, required)))
                        || qualified_call_owner_matches_import(call, import, required_imports)
                })
            })
        }
    }
}

fn declaration_binds_root(decl: &Decl, expected_root: &str) -> bool {
    // Adapters preserve both the concise source binding and, when available,
    // its complete lexical identity.  Either can be the root used at a call
    // site: `Client()` inside its namespace consults the concise binding,
    // while `Vendor::Queue::Client->new()` consults the qualified root.
    // Compare both compiler facts rather than reconstructing ownership from
    // source punctuation in shared analysis.
    std::iter::once(decl.name.as_str())
        .chain(decl.qualified_name.as_deref())
        .filter_map(|identity| bonsai_common::qualified_name_segments(identity).first().copied())
        .map(normalize_leading_call_punctuation)
        .map(str::trim)
        .any(|root| !root.is_empty() && root == expected_root)
}

fn qualified_call_owner_matches_import(
    call: &CallFact,
    import: &bonsai_lang_api::ImportSpec,
    required_imports: &[String],
) -> bool {
    if import.alias.is_some()
        || (!required_imports.is_empty()
            && !required_imports
                .iter()
                .any(|required| import_module_matches(&import.module, required)))
    {
        return false;
    }
    let owner = call
        .receiver
        .as_deref()
        .or_else(|| bonsai_common::qualified_name_owner(&call.callee))
        .map(bonsai_common::normalize_qualified_name);
    let imported = bonsai_common::normalize_qualified_name(&import.module);
    owner.is_some_and(|owner| {
        owner == imported
            || owner.starts_with(&format!("{imported}."))
            || required_imports.iter().any(|declared_alias| {
                let declared_alias = bonsai_common::normalize_qualified_name(declared_alias);
                owner == declared_alias || owner.starts_with(&format!("{declared_alias}."))
            })
    })
}

#[allow(clippy::too_many_arguments)] // Prepared matcher wrapper mirrors the exact callable-identity proof inputs.
fn prepared_call_binding_origin_is_invalid(
    prepared: &PreparedRule<'_>,
    bare_type_is_callable: bool,
    caller: &Decl,
    file_decls: Option<&[Decl]>,
    context: Option<&WorkspaceCallIdentityContext<'_>>,
    call: &CallFact,
    alias_map: &std::collections::HashMap<String, AliasTarget>,
    compiler_imports: Option<&bonsai_lang_api::ImportIndex>,
) -> bool {
    rule_primary_target(prepared.rule).is_some_and(|target| {
        target.binding_origin.is_some_and(|origin| {
            !call_binding_origin_is_valid(
                origin,
                bare_type_is_callable,
                caller,
                file_decls,
                context,
                call,
                alias_map,
                &prepared.rule.imports,
                compiler_imports,
            )
        })
    })
}

/// Resolve a function-shaped call against exact workspace declarations. `None` means no
/// workspace callable owns the spelling, so a rulepack-declared external
/// constructor may supply the identity. `Some(false)` includes lexical value
/// shadowing, ordinary functions, and mixed/ambiguous candidates.
fn resolve_workspace_call_candidates(
    context: &WorkspaceCallIdentityContext<'_>,
    call_name: &str,
    call_span: Span,
    alias_map: &std::collections::HashMap<String, AliasTarget>,
) -> Vec<bonsai_common::FuncId> {
    if bonsai_common::qualified_name_owner(call_name).is_none()
        && bonsai_callgraph::local_value_binding_shadows_callable(
            &context.caller.flow_events,
            call_name,
            call_span,
        )
    {
        return Vec::new();
    }
    let aliases: AHashMap<String, AliasTarget> = alias_map
        .iter()
        .map(|(name, target)| (name.clone(), target.clone()))
        .collect();
    let path_lookup = |file| {
        context
            .ws
            .vfs()
            .path(file)
            .ok()
            .map(|path| path.to_string_lossy().into_owned())
    };
    let capabilities = context
        .ws
        .db()
        .adapter_for(context.caller.span.file)
        .map(|adapter| adapter.capabilities())
        .unwrap_or_else(bonsai_lang_api::LanguageCapabilities::unsupported);
    let resolve_context =
        bonsai_resolve::ResolveContext::new(context.caller.span.file, &context.caller.module_path)
            .with_alias_map(&aliases)
            .with_file_path_lookup(&path_lookup)
            .with_same_directory_unqualified_calls(capabilities.same_directory_unqualified_calls)
            .with_module_path_syntax(capabilities.module_path_syntax);
    let mut candidates =
        bonsai_resolve::resolve_callable_with_context(context.global, call_name, &resolve_context);
    if bonsai_common::qualified_name_owner(call_name).is_none() && !aliases.contains_key(call_name) {
        // Module resolution supplies candidates; a nested callable's lexical
        // owner must also contain an unqualified, unimported call site. A
        // same-name helper in an unrelated function cannot shadow a runtime
        // binding or provide an external factory's return type.
        candidates.retain(|candidate| {
            let owner = context
                .global
                .decl_of(SymbolId::new(candidate.raw()))
                .and_then(|decl| decl.parent)
                .and_then(|parent| context.global.decl_of(parent));
            owner.is_none_or(|owner| {
                !matches!(
                    owner.kind,
                    DeclKind::Function | DeclKind::Method | DeclKind::Constructor
                ) || matcher_span_contains(owner.body_span.unwrap_or(owner.span), call_span)
            })
        });
    }
    candidates
}

fn workspace_call_resolves_as_constructor(
    context: &WorkspaceCallIdentityContext<'_>,
    call_name: &str,
    call_span: Span,
    alias_map: &std::collections::HashMap<String, AliasTarget>,
) -> Option<bool> {
    let candidates = resolve_workspace_call_candidates(context, call_name, call_span, alias_map);
    if candidates.is_empty() {
        return None;
    }
    Some(candidates.iter().all(|candidate| {
        context
            .global
            .decl_of(SymbolId::new(candidate.raw()))
            .is_some_and(|decl| decl.kind == DeclKind::Constructor)
    }))
}

/// Resolve the declared return type of one exact workspace call.
///
/// Every surviving callable candidate must declare the same non-empty return
/// type. Mixed, missing, or ambiguous return contracts fail closed. Imported
/// type aliases are expanded through compiler import facts before the type is
/// attached to the assignment target.
fn workspace_call_return_type(
    context: &WorkspaceCallIdentityContext<'_>,
    call_name: &str,
    call_span: Span,
    alias_map: &std::collections::HashMap<String, AliasTarget>,
) -> Option<String> {
    let candidates = resolve_workspace_call_candidates(context, call_name, call_span, alias_map);
    let mut resolved: Option<String> = None;
    for candidate in candidates {
        let decl = context.global.decl_of(SymbolId::new(candidate.raw()))?;
        let declared = if decl.kind == DeclKind::Constructor {
            let owner = decl.parent.and_then(|parent| context.global.decl_of(parent))?;
            if !matches!(
                owner.kind,
                DeclKind::Class | DeclKind::Struct | DeclKind::Enum | DeclKind::Trait | DeclKind::Interface
            ) {
                return None;
            }
            owner
                .qualified_name
                .as_deref()
                .filter(|name| !name.trim().is_empty())
                .unwrap_or(owner.name.as_str())
                .to_string()
        } else {
            let declared = decl
                .return_type
                .as_deref()
                .map(str::trim)
                .filter(|return_type| !return_type.is_empty())?;
            // Return annotations are written in the callee's lexical import
            // scope, not the caller's. Canonicalizing through caller aliases
            // silently loses types whenever a helper imports/renames its
            // result type and a different module calls that helper.
            let callee_aliases = context
                .ws
                .db()
                .compiler_import_index_uncached(decl.span.file)
                .as_ref()
                .map(bonsai_lang_api::alias_map_from_imports)
                .unwrap_or_default();
            expand_callee_alias(declared, &callee_aliases).unwrap_or_else(|| declared.to_string())
        };
        let canonical = declared;
        if resolved.as_deref().is_some_and(|existing| existing != canonical) {
            return None;
        }
        resolved = Some(canonical);
    }
    resolved
}

/// Resolve an exact first-party call result from either its declared return
/// type or a compiler-proven, rulepack-typed return value.
///
/// The fallback is deliberately narrow: every resolved callable must have a
/// complete body whose normal exits return the same typed place. The place
/// type itself comes from generic compiler aliases or a rulepack-declared
/// external factory. Shared analysis never assigns meaning to a provider or
/// method spelling, and an untyped/mixed/fallthrough return fails closed.
fn workspace_call_return_type_with_rulepack(
    context: &WorkspaceCallIdentityContext<'_>,
    call_name: &str,
    call_span: Span,
    alias_map: &std::collections::HashMap<String, AliasTarget>,
    factory: &RulepackTyping,
    language: Option<&str>,
) -> Option<String> {
    if let Some(declared) = workspace_call_return_type(context, call_name, call_span, alias_map) {
        return Some(declared);
    }
    let language = language?;
    let candidates = resolve_workspace_call_candidates(context, call_name, call_span, alias_map);
    if candidates.is_empty() {
        return None;
    }
    let mut resolved: Option<String> = None;
    for candidate in candidates {
        let inferred =
            infer_rulepack_typed_decl_return(context, SymbolId::new(candidate.raw()), factory, language)?;
        if resolved.as_deref().is_some_and(|existing| existing != inferred) {
            return None;
        }
        resolved = Some(inferred);
    }
    resolved
}

fn infer_rulepack_typed_decl_return(
    context: &WorkspaceCallIdentityContext<'_>,
    symbol: SymbolId,
    factory: &RulepackTyping,
    language: &str,
) -> Option<String> {
    let decl = context.ws.exact_decl(symbol)?;
    if decl.kind == DeclKind::Constructor || decl.flow_events.is_empty() {
        return None;
    }
    let file_index = context.ws.exact_decl_index_shared(decl.span.file)?;
    let compiler_imports = context.ws.db().compiler_import_index_uncached(decl.span.file);
    let mut aliases = compiler_imports
        .as_ref()
        .map(bonsai_lang_api::alias_map_from_imports)
        .unwrap_or_default();
    extend_alias_map_with_declared_types(&mut aliases, &decl.type_aliases);
    bonsai_lang_api::extend_alias_map_with_flow_events(&mut aliases, &decl.flow_events);
    let callee_context = WorkspaceCallIdentityContext {
        ws: context.ws,
        global: context.global,
        caller: &decl,
    };
    let derived = synth_factory_type_aliases(
        &decl.flow_events,
        &file_index.assignment_values,
        factory,
        language,
        &aliases,
        compiler_imports.as_ref(),
        Some(&decl),
        Some(&callee_context),
    );
    extend_alias_map_with_declared_types(&mut aliases, &derived);

    if !flow_events_guarantee_exit(&decl.flow_events) {
        return None;
    }
    let mut returns = Vec::new();
    if !collect_typed_return_places(&decl.flow_events, &aliases, &mut returns) || returns.is_empty() {
        return None;
    }
    returns.sort();
    returns.dedup();
    (returns.len() == 1).then(|| returns.pop().expect("single inferred return type"))
}

fn collect_typed_return_places(
    events: &[FlowEvent],
    aliases: &std::collections::HashMap<String, AliasTarget>,
    out: &mut Vec<String>,
) -> bool {
    for event in events {
        match event {
            FlowEvent::Return {
                value_name,
                value_flow,
                ..
            } => {
                let Some(place) = value_flow.place.as_deref().or(value_name.as_deref()) else {
                    return false;
                };
                let place = normalize_leading_call_punctuation(place.trim());
                let Some(AliasTarget::Type { type_name }) = aliases.get(place) else {
                    return false;
                };
                if type_name.trim().is_empty() {
                    return false;
                }
                out.push(type_name.clone());
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                if !collect_typed_return_places(then_events, aliases, out)
                    || !collect_typed_return_places(else_events, aliases, out)
                {
                    return false;
                }
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                if !collect_typed_return_places(body, aliases, out) {
                    return false;
                }
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                if !collect_typed_return_places(body, aliases, out)
                    || !collect_typed_return_places(catch_events, aliases, out)
                    || !collect_typed_return_places(finally_events, aliases, out)
                {
                    return false;
                }
            }
            _ => {}
        }
    }
    true
}

/// Conservative normal-exit proof for inferred return summaries. A final
/// return/throw terminates the sequence; a branch must terminate on both
/// sides. Loops and partial try/catch constructs never become total merely
/// because one nested arm returns.
fn flow_events_guarantee_exit(events: &[FlowEvent]) -> bool {
    for event in events {
        match event {
            FlowEvent::Return { .. } | FlowEvent::Throw { .. } => return true,
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } if !else_events.is_empty()
                && flow_events_guarantee_exit(then_events)
                && flow_events_guarantee_exit(else_events) =>
            {
                return true;
            }
            FlowEvent::Try { finally_events, .. } if flow_events_guarantee_exit(finally_events) => {
                return true
            }
            FlowEvent::Using { body, .. } if flow_events_guarantee_exit(body) => {
                return true;
            }
            _ => {}
        }
    }
    false
}

type ExactModuleFileIndexKey = (u64, u64, bonsai_index::GlobalIndexIdentity);

/// Candidate directory for exact workspace-module lookup.
///
/// The final verdict still runs the resolver's exact module/path predicates.
/// This index only replaces the accidental `imports x workspace-files` scan:
/// any exact module or path match must share its terminal normalized segment
/// with the target, so the leaf directory is a complete candidate set.
#[derive(Default)]
struct ExactModuleFileIndex {
    files_by_leaf: AHashMap<String, Vec<FileId>>,
}

impl ExactModuleFileIndex {
    fn build(ws: &Workspace, global: &bonsai_index::GlobalIndex) -> Arc<Self> {
        let mut files_by_leaf: AHashMap<String, Vec<FileId>> = AHashMap::new();
        for file in global.all_files() {
            let mut file_leaves = AHashSet::new();
            for decl in global
                .decls_in(file)
                .iter()
                .filter(|decl| decl.kind == DeclKind::Module)
            {
                if let Some(leaf) = decl.module_path.segments.last() {
                    if !leaf.is_empty() {
                        file_leaves.insert(leaf.clone());
                    }
                }
            }
            if let Ok(path) = ws.vfs().path(file) {
                for part in bonsai_resolve::module_path_parts(&path.to_string_lossy()) {
                    if !part.is_empty() {
                        file_leaves.insert(part);
                    }
                }
            }
            for leaf in file_leaves {
                files_by_leaf.entry(leaf).or_default().push(file);
            }
        }
        for files in files_by_leaf.values_mut() {
            files.sort_unstable();
            files.dedup();
        }
        Arc::new(Self { files_by_leaf })
    }

    fn candidate_files(&self, target: &str) -> Vec<FileId> {
        let mut leaves = AHashSet::new();
        if let Some(leaf) = bonsai_common::qualified_name_segments(target).last() {
            if !leaf.is_empty() {
                leaves.insert((*leaf).to_string());
            }
        }
        if let Some(leaf) = bonsai_resolve::module_target_parts(target).last() {
            if !leaf.is_empty() {
                leaves.insert(leaf.clone());
            }
        }
        let mut candidates = leaves
            .into_iter()
            .filter_map(|leaf| self.files_by_leaf.get(&leaf))
            .flat_map(|files| files.iter().copied())
            .collect::<Vec<_>>();
        candidates.sort_unstable();
        candidates.dedup();
        candidates
    }
}

fn estimated_exact_module_file_index_bytes(index: &ExactModuleFileIndex) -> u64 {
    index.files_by_leaf.iter().fold(1024_u64, |total, (leaf, files)| {
        total
            .saturating_add(96)
            .saturating_add(u64::try_from(leaf.len()).unwrap_or(u64::MAX))
            .saturating_add(
                u64::try_from(files.len())
                    .unwrap_or(u64::MAX)
                    .saturating_mul(std::mem::size_of::<FileId>() as u64),
            )
    })
}

static EXACT_MODULE_FILE_INDEX_CACHE: std::sync::LazyLock<
    MatcherFactCache<ExactModuleFileIndexKey, ExactModuleFileIndex>,
> = std::sync::LazyLock::new(|| {
    MatcherFactCache::new_with_oversized_singleton(matcher_fact_cache_budget_share(1, 8), true)
});

type ModuleExportTypeKey = (u64, u64, bonsai_index::GlobalIndexIdentity, FileId, u64, String);

static MODULE_EXPORT_TYPE_CACHE: std::sync::LazyLock<
    MatcherFactCache<ModuleExportTypeKey, Vec<TypeAliasBinding>>,
> = std::sync::LazyLock::new(|| MatcherFactCache::new(matcher_fact_cache_budget_share(1, 8)));

fn estimated_type_alias_bytes(aliases: &[TypeAliasBinding]) -> u64 {
    aliases.iter().fold(64_u64, |total, alias| {
        total
            .saturating_add(64)
            .saturating_add(u64::try_from(alias.name.len()).unwrap_or(u64::MAX))
            .saturating_add(u64::try_from(alias.type_name.len()).unwrap_or(u64::MAX))
    })
}

fn exact_module_file_index(ws: &Workspace, global: &bonsai_index::GlobalIndex) -> Arc<ExactModuleFileIndex> {
    let key = (
        ws.db().vfs().instance_id(),
        ws.db().vfs().revision(),
        global.identity(),
    );
    EXACT_MODULE_FILE_INDEX_CACHE.get_or_insert_with(
        key,
        || ExactModuleFileIndex::build(ws, global),
        estimated_exact_module_file_index_bytes,
    )
}

fn exact_module_file_for_import_target(
    ws: &Workspace,
    global: &bonsai_index::GlobalIndex,
    target: &str,
) -> Option<FileId> {
    let module_files = exact_module_file_index(ws, global);
    let mut candidates = Vec::new();
    for file in module_files.candidate_files(target) {
        let syntax = ws
            .db()
            .adapter_for(file)
            .map(|adapter| adapter.capabilities().module_path_syntax)
            .unwrap_or_else(bonsai_lang_api::ModulePathSyntax::none);
        let module_matches = global.decls_in(file).iter().any(|decl| {
            decl.kind == DeclKind::Module
                && bonsai_resolve::module_target_exactly_matches_decl_module_path_with_syntax(
                    target,
                    &decl.module_path,
                    syntax,
                )
        });
        let path_matches =
            ws.vfs().path(file).ok().is_some_and(|path| {
                bonsai_resolve::module_target_matches_path(target, &path.to_string_lossy())
            });
        if module_matches || path_matches {
            candidates.push(file);
        }
    }
    candidates.sort_unstable();
    candidates.dedup();
    match candidates.as_slice() {
        [file] => Some(*file),
        _ => None,
    }
}

fn flow_events_rebind_prefix(events: &[FlowEvent], prefix: &str) -> bool {
    for event in events {
        match event {
            FlowEvent::Assign { target, .. } | FlowEvent::AggregateAssign { target, .. }
                if target == prefix || target.starts_with(&format!("{prefix}.")) =>
            {
                return true;
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                if flow_events_rebind_prefix(then_events, prefix)
                    || flow_events_rebind_prefix(else_events, prefix)
                {
                    return true;
                }
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                if flow_events_rebind_prefix(body, prefix) {
                    return true;
                }
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                if flow_events_rebind_prefix(body, prefix)
                    || flow_events_rebind_prefix(catch_events, prefix)
                    || flow_events_rebind_prefix(finally_events, prefix)
                {
                    return true;
                }
            }
            _ => {}
        }
    }
    false
}

fn module_header_export_type_aliases(
    ws: &Workspace,
    global: &bonsai_index::GlobalIndex,
    file: FileId,
    factory: &RulepackTyping,
    language: Option<&str>,
) -> Arc<Vec<TypeAliasBinding>> {
    let key = (
        ws.db().vfs().instance_id(),
        ws.db().vfs().revision(),
        global.identity(),
        file,
        factory.fingerprint,
        language.unwrap_or_default().to_string(),
    );
    MODULE_EXPORT_TYPE_CACHE.get_or_insert_with(
        key,
        || {
            Arc::new(build_module_header_export_type_aliases(
                ws, global, file, factory, language,
            ))
        },
        |aliases| estimated_type_alias_bytes(aliases),
    )
}

fn build_module_header_export_type_aliases(
    ws: &Workspace,
    global: &bonsai_index::GlobalIndex,
    file: FileId,
    factory: &RulepackTyping,
    language: Option<&str>,
) -> Vec<TypeAliasBinding> {
    let Some(module_decl) = global
        .decls_in(file)
        .iter()
        .find(|decl| decl.kind == DeclKind::Module || decl.name == bonsai_lang_api::MODULE_DECL_NAME)
    else {
        return Vec::new();
    };
    let Some(syntax) = ws.db().compiler_syntax_header_uncached(file) else {
        return Vec::new();
    };
    let compiler_imports = ws.db().compiler_import_index_uncached(file);
    let mut alias_map = compiler_imports
        .as_ref()
        .map(bonsai_lang_api::alias_map_from_imports)
        .unwrap_or_default();
    extend_alias_map_with_declared_types(&mut alias_map, &module_decl.type_aliases);
    let assignments = syntax
        .factory_assignments
        .iter()
        .filter(|assignment| assignment.owner_span == module_decl.span)
        .collect::<Vec<_>>();
    let ordinary_aliases = syntax
        .assignment_aliases
        .iter()
        .filter(|assignment| assignment.owner_span == module_decl.span)
        .cloned()
        .collect::<Vec<_>>();
    extend_alias_map_with_compiler_assignment_aliases(&mut alias_map, &ordinary_aliases);
    let context = WorkspaceCallIdentityContext {
        ws,
        global,
        caller: module_decl,
    };
    let specs = language
        .and_then(|language| factory.specs_for(language))
        .unwrap_or_default();
    let mut out = module_decl.type_aliases.clone();
    loop {
        let prior_len = out.len();
        for assignment in &assignments {
            let call_root = bonsai_common::qualified_name_segments(&assignment.call_name)
                .first()
                .copied()
                .map(normalize_leading_call_punctuation)
                .unwrap_or_default();
            let rebound_before_call = ordinary_aliases.iter().any(|alias| {
                alias.assignment_span.start < assignment.assignment_span.start
                    && (alias.target == call_root || alias.target.starts_with(&format!("{call_root}.")))
            }) || assignments.iter().any(|prior| {
                prior.assignment_span.start < assignment.assignment_span.start
                    && (prior.target == call_root || prior.target.starts_with(&format!("{call_root}.")))
            });
            if !call_root.is_empty() && rebound_before_call {
                continue;
            }

            let call = CallFact {
                callee: assignment.call_name.clone(),
                receiver: assignment.call_receiver.clone(),
                span: assignment.assignment_span,
                args: Vec::new(),
                receiver_types: Vec::new(),
                call_kind: CallKind::Function,
                origin: CallFactOrigin::AssignmentSourceCall,
            };
            let mut candidate_types = Vec::new();
            if let Some(type_name) = workspace_call_return_type(
                &context,
                &assignment.call_name,
                assignment.assignment_span,
                &alias_map,
            ) {
                push_unique_string(&mut candidate_types, type_name);
            }
            for spec in specs {
                if !typing_imports_allow(&spec.required_imports, compiler_imports.as_ref()) {
                    continue;
                }
                if let Some(origin) = spec.binding_origin {
                    if !call_binding_origin_is_valid(
                        origin,
                        ws.db()
                            .adapter_for(file)
                            .is_some_and(|adapter| adapter.capabilities().bare_call_constructor_syntax),
                        module_decl,
                        Some(global.decls_in(file)),
                        Some(&context),
                        &call,
                        &alias_map,
                        &spec.required_imports,
                        compiler_imports.as_ref(),
                    ) {
                        continue;
                    }
                }
                if !factory_spec_matches_call(
                    &assignment.call_name,
                    assignment.call_receiver.as_deref(),
                    spec,
                    &alias_map,
                ) {
                    continue;
                }
                if spec.kind == MatchKind::New
                    && workspace_call_resolves_as_constructor(
                        &context,
                        &assignment.call_name,
                        assignment.assignment_span,
                        &alias_map,
                    ) == Some(false)
                {
                    continue;
                }
                push_unique_string(&mut candidate_types, spec.type_name.clone());
            }
            if candidate_types.len() == 1 {
                let binding = TypeAliasBinding {
                    name: assignment.target.clone(),
                    type_name: candidate_types.pop().expect("single module export type"),
                };
                if !out.contains(&binding) {
                    out.push(binding);
                }
            }
        }
        if out.len() == prior_len {
            break;
        }
        extend_alias_map_with_declared_types(&mut alias_map, &out[prior_len..]);
    }
    out.sort_by(|left, right| (&left.name, &left.type_name).cmp(&(&right.name, &right.type_name)));
    out.dedup();
    out
}

fn imported_module_value_type_aliases(
    ws: &Workspace,
    global: &bonsai_index::GlobalIndex,
    file_index: &DeclIndex,
    factory: &RulepackTyping,
    language: Option<&str>,
    compiler_imports: Option<&bonsai_lang_api::ImportIndex>,
) -> Vec<TypeAliasBinding> {
    let Some(compiler_imports) = compiler_imports else {
        return Vec::new();
    };
    let compiler_aliases = bonsai_lang_api::alias_map_from_imports(compiler_imports);
    let mut out = Vec::new();
    for (local, target) in compiler_aliases {
        if local.starts_with(bonsai_lang_api::WILDCARD_IMPORT_ALIAS_PREFIX)
            || file_index
                .defs
                .iter()
                .any(|decl| flow_events_rebind_prefix(&decl.flow_events, &local))
        {
            continue;
        }
        let (module_target, imported_member) = match target {
            AliasTarget::Namespace { module } => (module, None),
            AliasTarget::Member { module, member } => {
                let nested_module = format!("{module}.{member}");
                if exact_module_file_for_import_target(ws, global, &nested_module).is_some() {
                    (nested_module, None)
                } else {
                    (module, Some(member))
                }
            }
            AliasTarget::Type { .. } => continue,
        };
        let Some(target_file) = exact_module_file_for_import_target(ws, global, &module_target) else {
            continue;
        };
        let exported = module_header_export_type_aliases(ws, global, target_file, factory, language);
        if let Some(member) = imported_member {
            let mut types = exported
                .iter()
                .filter(|binding| binding.name == member)
                .map(|binding| binding.type_name.clone())
                .collect::<Vec<_>>();
            types.sort();
            types.dedup();
            if types.len() == 1 {
                out.push(TypeAliasBinding {
                    name: local,
                    type_name: types.pop().expect("single imported member type"),
                });
            }
        } else {
            for binding in exported.iter() {
                out.push(TypeAliasBinding {
                    name: format!("{local}.{}", binding.name),
                    type_name: binding.type_name.clone(),
                });
            }
        }
    }
    out.sort_by(|left, right| (&left.name, &left.type_name).cmp(&(&right.name, &right.type_name)));
    out.dedup();
    out
}

/// Synthesize assignment receiver types from compiler-resolved first-party
/// calls. This is independent of rulepack factory models: source declarations
/// own their return contracts, while the resolver owns callable identity.
fn synth_workspace_call_result_type_aliases(
    events: &[FlowEvent],
    context: &WorkspaceCallIdentityContext<'_>,
    alias_map: &std::collections::HashMap<String, AliasTarget>,
    factory: &RulepackTyping,
    language: Option<&str>,
) -> Vec<TypeAliasBinding> {
    fn walk(
        events: &[FlowEvent],
        context: &WorkspaceCallIdentityContext<'_>,
        alias_map: &std::collections::HashMap<String, AliasTarget>,
        factory: &RulepackTyping,
        language: Option<&str>,
        out: &mut Vec<TypeAliasBinding>,
    ) {
        for event in events {
            match event {
                FlowEvent::Assign {
                    span,
                    target,
                    source_call: Some(call_name),
                    ..
                } if !target.is_empty() => {
                    if let Some(type_name) = workspace_call_return_type_with_rulepack(
                        context, call_name, *span, alias_map, factory, language,
                    ) {
                        let binding = TypeAliasBinding {
                            name: target.clone(),
                            type_name,
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
                    walk(then_events, context, alias_map, factory, language, out);
                    walk(else_events, context, alias_map, factory, language, out);
                }
                FlowEvent::Loop { body, .. }
                | FlowEvent::Defer { body, .. }
                | FlowEvent::Using { body, .. } => {
                    walk(body, context, alias_map, factory, language, out);
                }
                FlowEvent::Try {
                    body,
                    catch_events,
                    finally_events,
                    ..
                } => {
                    walk(body, context, alias_map, factory, language, out);
                    walk(catch_events, context, alias_map, factory, language, out);
                    walk(finally_events, context, alias_map, factory, language, out);
                }
                _ => {}
            }
        }
    }

    let mut out = Vec::new();
    walk(events, context, alias_map, factory, language, &mut out);
    out
}

fn call_has_new_identity(
    context: Option<&WorkspaceCallIdentityContext<'_>>,
    factory: &RulepackTyping,
    language: &str,
    call: &CallFact,
    alias_map: &std::collections::HashMap<String, AliasTarget>,
    compiler_imports: Option<&bonsai_lang_api::ImportIndex>,
) -> bool {
    if call.call_kind == CallKind::Constructor {
        return true;
    }
    let Some(context) = context else {
        // A function-shaped CST call needs workspace identity to distinguish
        // a declared constructor from a same-spelled value or function.
        // Failing closed prevents external YAML typing from overriding the
        // compiler's lexical scope.
        return false;
    };
    if let Some(resolved) =
        workspace_call_resolves_as_constructor(context, &call.callee, call.span, alias_map)
    {
        return resolved;
    }
    rulepack_constructor_matches_call(
        factory,
        language,
        &call.callee,
        call_receiver_text(&call.callee),
        alias_map,
        compiler_imports,
    )
}

/// Derive return types for exact call expressions used as the parsed receiver
/// of an assignment's direct value producer.
///
/// This is the assignment/accessor counterpart to
/// [`synth_exact_call_expression_type_aliases`]. Some grammars lower a getter
/// such as `Factory(x).value` without an outer call node. The frontend still
/// records the getter's exact receiver span and the nested call span. Joining
/// those compiler facts here lets rulepack typing describe the provider while
/// shared matching remains independent of language punctuation and API names.
#[allow(clippy::too_many_arguments)]
fn synth_exact_assignment_receiver_type_aliases(
    calls: &[CallFact],
    assignment_values: &[bonsai_lang_api::AssignmentValueFact],
    specs: &[FactoryReturnSpec],
    alias_map: &std::collections::HashMap<String, AliasTarget>,
    compiler_imports: Option<&bonsai_lang_api::ImportIndex>,
    caller: Option<&Decl>,
    workspace_context: Option<&WorkspaceCallIdentityContext<'_>>,
) -> Vec<TypeAliasBinding> {
    let mut candidates_by_expression: AHashMap<String, Vec<String>> = AHashMap::new();
    for fact in assignment_values {
        let (Some(expression), Some(receiver_span)) = (
            fact.direct_call_receiver.as_deref().map(str::trim),
            fact.direct_call_receiver_span,
        ) else {
            continue;
        };
        if expression.is_empty() || !fact.call_sites.contains(&receiver_span) {
            continue;
        }
        let Some(call) = calls
            .iter()
            .filter(|call| {
                call.span.file == receiver_span.file
                    && call.span.start == receiver_span.start
                    && call.span.end <= receiver_span.end
            })
            .max_by_key(|call| call.span.end)
        else {
            continue;
        };

        let mut candidate_types = Vec::new();
        let expanded = expand_callee_alias(&call.callee, alias_map);
        if let Some(context) = workspace_context {
            if let Some(type_name) = workspace_call_return_type(context, &call.callee, call.span, alias_map) {
                push_unique_string(&mut candidate_types, type_name);
            }
        }
        for spec in specs {
            if !typing_imports_allow(&spec.required_imports, compiler_imports) {
                continue;
            }
            if let Some(origin) = spec.binding_origin {
                let Some(caller) = caller else {
                    continue;
                };
                if !call_binding_origin_is_valid(
                    origin,
                    workspace_context
                        .and_then(|context| context.ws.db().adapter_for(caller.name_span.file))
                        .is_some_and(|adapter| adapter.capabilities().bare_call_constructor_syntax),
                    caller,
                    None,
                    workspace_context,
                    call,
                    alias_map,
                    &spec.required_imports,
                    compiler_imports,
                ) {
                    continue;
                }
            }
            if !factory_spec_matches_call(&call.callee, call.receiver.as_deref(), spec, alias_map)
                && !expanded
                    .as_deref()
                    .is_some_and(|expanded| factory_spec_matches_call(expanded, None, spec, alias_map))
            {
                continue;
            }
            if spec.kind == MatchKind::New {
                let Some(workspace_context) = workspace_context else {
                    continue;
                };
                if workspace_call_resolves_as_constructor(
                    workspace_context,
                    &call.callee,
                    call.span,
                    alias_map,
                ) == Some(false)
                {
                    continue;
                }
            }
            push_unique_string(&mut candidate_types, spec.type_name.clone());
        }
        if candidate_types.len() == 1 {
            let type_name = candidate_types.pop().expect("single candidate type");
            push_unique_string(
                candidates_by_expression
                    .entry(expression.to_string())
                    .or_default(),
                type_name,
            );
        }
    }

    let mut out = candidates_by_expression
        .into_iter()
        .filter_map(|(name, mut types)| {
            (types.len() == 1).then(|| TypeAliasBinding {
                name,
                type_name: types.pop().expect("single expression type"),
            })
        })
        .collect::<Vec<_>>();
    out.sort_by(|left, right| (&left.name, &left.type_name).cmp(&(&right.name, &right.type_name)));
    out
}

/// Synthesize `local → ReturnType` aliases for assignments whose RHS is a
/// factory call or constructor named in rulepack metadata. Empty (no
/// allocation) when the pack declares no matching call-result type.
#[allow(clippy::too_many_arguments)] // Factory typing joins rule semantics to exact calls, assignments, imports, and workspace identity.
fn synth_factory_type_aliases(
    events: &[FlowEvent],
    assignment_values: &[bonsai_lang_api::AssignmentValueFact],
    factory: &RulepackTyping,
    language: &str,
    alias_map: &std::collections::HashMap<String, AliasTarget>,
    compiler_imports: Option<&bonsai_lang_api::ImportIndex>,
    caller: Option<&Decl>,
    workspace_context: Option<&WorkspaceCallIdentityContext<'_>>,
) -> Vec<TypeAliasBinding> {
    let Some(specs) = factory.specs_for(language) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let calls = collect_calls(events);
    #[allow(clippy::too_many_arguments)] // Recursive traversal threads immutable factory evidence and one output accumulator.
    fn walk(
        events: &[FlowEvent],
        assignment_values: &[bonsai_lang_api::AssignmentValueFact],
        specs: &[FactoryReturnSpec],
        alias_map: &std::collections::HashMap<String, AliasTarget>,
        compiler_imports: Option<&bonsai_lang_api::ImportIndex>,
        caller: Option<&Decl>,
        workspace_context: Option<&WorkspaceCallIdentityContext<'_>>,
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
                    let call_identity = CallFact {
                        callee: call_name.to_string(),
                        receiver: call_receiver.map(str::to_string),
                        span: *span,
                        args: Vec::new(),
                        receiver_types: Vec::new(),
                        call_kind: CallKind::Function,
                        origin: CallFactOrigin::AssignmentSourceCall,
                    };
                    for spec in specs {
                        if !typing_imports_allow(&spec.required_imports, compiler_imports) {
                            continue;
                        }
                        if let Some(origin) = spec.binding_origin {
                            let Some(caller) = caller else {
                                continue;
                            };
                            if !call_binding_origin_is_valid(
                                origin,
                                workspace_context
                                    .and_then(|context| context.ws.db().adapter_for(caller.name_span.file))
                                    .is_some_and(|adapter| {
                                        adapter.capabilities().bare_call_constructor_syntax
                                    }),
                                caller,
                                None,
                                workspace_context,
                                &call_identity,
                                alias_map,
                                &spec.required_imports,
                                compiler_imports,
                            ) {
                                continue;
                            }
                        }
                        if !factory_spec_matches_call(call_name, call_receiver, spec, alias_map)
                            && !expanded.as_deref().is_some_and(|expanded| {
                                factory_spec_matches_call(expanded, None, spec, alias_map)
                            })
                        {
                            continue;
                        }
                        if spec.kind == MatchKind::New {
                            let Some(workspace_context) = workspace_context else {
                                continue;
                            };
                            if workspace_call_resolves_as_constructor(
                                workspace_context,
                                call_name,
                                *span,
                                alias_map,
                            ) == Some(false)
                            {
                                continue;
                            }
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
                    walk(
                        then_events,
                        assignment_values,
                        specs,
                        alias_map,
                        compiler_imports,
                        caller,
                        workspace_context,
                        out,
                    );
                    walk(
                        else_events,
                        assignment_values,
                        specs,
                        alias_map,
                        compiler_imports,
                        caller,
                        workspace_context,
                        out,
                    );
                }
                FlowEvent::Loop { body, .. }
                | FlowEvent::Defer { body, .. }
                | FlowEvent::Using { body, .. } => {
                    walk(
                        body,
                        assignment_values,
                        specs,
                        alias_map,
                        compiler_imports,
                        caller,
                        workspace_context,
                        out,
                    );
                }
                FlowEvent::Try {
                    body,
                    catch_events,
                    finally_events,
                    ..
                } => {
                    walk(
                        body,
                        assignment_values,
                        specs,
                        alias_map,
                        compiler_imports,
                        caller,
                        workspace_context,
                        out,
                    );
                    walk(
                        catch_events,
                        assignment_values,
                        specs,
                        alias_map,
                        compiler_imports,
                        caller,
                        workspace_context,
                        out,
                    );
                    walk(
                        finally_events,
                        assignment_values,
                        specs,
                        alias_map,
                        compiler_imports,
                        caller,
                        workspace_context,
                        out,
                    );
                }
                _ => {}
            }
        }
    }
    // Factory return types form a finite monotone relation over the
    // declaration's assignment targets. Derive it to a fixed point so an
    // exact rule chain such as `client_factory() -> Client`, followed by
    // `client.session() -> Session`, types the second receiver without any
    // provider names or depth limit in shared analysis.
    //
    // `walk` de-duplicates `(binding, type)` pairs, and both the assignment
    // targets and typing specs are finite. Therefore each non-terminal pass
    // adds at least one fact and the uncapped loop terminates naturally.
    let mut resolved_aliases = alias_map.clone();
    loop {
        let prior_len = out.len();
        for alias in synth_exact_assignment_receiver_type_aliases(
            &calls,
            assignment_values,
            specs,
            &resolved_aliases,
            compiler_imports,
            caller,
            workspace_context,
        ) {
            if !out.contains(&alias) {
                out.push(alias);
            }
        }
        extend_alias_map_with_declared_types(&mut resolved_aliases, &out[prior_len..]);
        walk(
            events,
            assignment_values,
            specs,
            &resolved_aliases,
            compiler_imports,
            caller,
            workspace_context,
            &mut out,
        );
        if out.len() == prior_len {
            break;
        }
        extend_alias_map_with_declared_types(&mut resolved_aliases, &out[prior_len..]);
    }
    out
}

/// Derive rulepack-declared types for immutable receiver fields initialized
/// by exact compiler call facts, then expose those types to methods of the
/// owning class.
///
/// A field initializer belongs to class state rather than to an arbitrary
/// sibling callable. Language adapters prove that relationship through
/// `AssignmentValueFact::target_owner` and `target_is_immutable`; this helper
/// consumes those facts without interpreting field names, provider names, or
/// source-language syntax. The concise field identity is obtained from the
/// adapter-normalized place using the shared qualified-name helper, and local
/// flow bindings are layered afterward so ordinary lexical shadowing still
/// wins.
#[allow(clippy::too_many_arguments)]
fn synth_class_field_type_aliases(
    ws: &Workspace,
    file_index: &DeclIndex,
    decl: &Decl,
    factory: &RulepackTyping,
    language: &str,
    alias_map: &std::collections::HashMap<String, AliasTarget>,
    compiler_imports: Option<&bonsai_lang_api::ImportIndex>,
    global_headers: Option<&GlobalIndex>,
) -> Vec<TypeAliasBinding> {
    let Some(specs) = factory.specs_for(language) else {
        return Vec::new();
    };

    let mut visible_owners = Vec::new();
    let mut current = Some(decl.symbol);
    while let Some(symbol) = current {
        visible_owners.push(symbol);
        current = file_index
            .defs
            .iter()
            .find(|candidate| candidate.symbol == symbol)
            .and_then(|candidate| candidate.parent);
    }
    let field_initializers = file_index
        .assignment_values
        .iter()
        .filter(|fact| {
            fact.target_is_immutable
                && fact
                    .target_owner
                    .is_some_and(|owner| visible_owners.contains(&owner))
                && fact.target.is_some()
                && fact.direct_call_name.is_some()
        })
        .collect::<Vec<_>>();
    if field_initializers.is_empty() {
        return Vec::new();
    }

    let mut out = Vec::new();
    let mut resolved_aliases = alias_map.clone();
    loop {
        let prior_len = out.len();
        for fact in &field_initializers {
            let (Some(target), Some(call_name)) = (fact.target.as_deref(), fact.direct_call_name.as_deref())
            else {
                continue;
            };
            let Some(owner) = fact
                .target_owner
                .and_then(|owner| file_index.defs.iter().find(|candidate| candidate.symbol == owner))
            else {
                continue;
            };
            let call_span = fact.direct_call_span.unwrap_or(fact.assignment_span);
            let call = CallFact {
                callee: call_name.to_string(),
                receiver: fact.direct_call_receiver.clone(),
                span: call_span,
                args: Vec::new(),
                receiver_types: Vec::new(),
                call_kind: if fact.direct_call_receiver.is_some() {
                    CallKind::Method
                } else {
                    CallKind::Function
                },
                origin: CallFactOrigin::AssignmentSourceCall,
            };
            let workspace_context = global_headers.map(|global| WorkspaceCallIdentityContext {
                ws,
                global,
                caller: owner,
            });
            let mut candidate_types = Vec::new();
            if let Some(context) = workspace_context.as_ref() {
                if let Some(type_name) =
                    workspace_call_return_type(context, call_name, call_span, &resolved_aliases)
                {
                    push_unique_string(&mut candidate_types, type_name);
                }
            }
            let expanded = expand_callee_alias(call_name, &resolved_aliases);
            for spec in specs {
                if !typing_imports_allow(&spec.required_imports, compiler_imports) {
                    continue;
                }
                if let Some(origin) = spec.binding_origin {
                    if !call_binding_origin_is_valid(
                        origin,
                        ws.db()
                            .adapter_for(owner.span.file)
                            .is_some_and(|adapter| adapter.capabilities().bare_call_constructor_syntax),
                        owner,
                        Some(&file_index.defs),
                        workspace_context.as_ref(),
                        &call,
                        &resolved_aliases,
                        &spec.required_imports,
                        compiler_imports,
                    ) {
                        continue;
                    }
                }
                if !factory_spec_matches_call(
                    call_name,
                    fact.direct_call_receiver.as_deref(),
                    spec,
                    &resolved_aliases,
                ) && !expanded.as_deref().is_some_and(|expanded| {
                    factory_spec_matches_call(expanded, None, spec, &resolved_aliases)
                }) {
                    continue;
                }
                if spec.kind == MatchKind::New
                    && workspace_context.as_ref().is_some_and(|context| {
                        workspace_call_resolves_as_constructor(
                            context,
                            call_name,
                            call_span,
                            &resolved_aliases,
                        ) == Some(false)
                    })
                {
                    continue;
                }
                push_unique_string(&mut candidate_types, spec.type_name.clone());
            }
            let [type_name] = candidate_types.as_slice() else {
                continue;
            };
            let mut names = vec![target.to_string()];
            let tail = bonsai_common::short_qualified_tail(target).trim();
            if is_simple_identifier(tail) && !names.iter().any(|name| name == tail) {
                names.push(tail.to_string());
            }
            for name in names {
                let alias = TypeAliasBinding {
                    name,
                    type_name: type_name.clone(),
                };
                if !out.contains(&alias) {
                    out.push(alias);
                }
            }
        }
        if out.len() == prior_len {
            break;
        }
        extend_alias_map_with_declared_types(&mut resolved_aliases, &out[prior_len..]);
    }
    out.sort_by(|left, right| (&left.name, &left.type_name).cmp(&(&right.name, &right.type_name)));
    out.dedup();
    let mut ambiguous = AHashSet::new();
    for pair in out.windows(2) {
        if pair[0].name == pair[1].name && pair[0].type_name != pair[1].type_name {
            ambiguous.insert(pair[0].name.clone());
        }
    }
    out.retain(|alias| !ambiguous.contains(&alias.name));
    out
}

/// Type an exact compiler call expression when that expression is used
/// directly as the receiver of another call.
///
/// Assignment typing alone covers `val statement = connection.createStatement()`
/// followed by `statement.execute(...)`, but it does not cover the semantically
/// identical direct chain `connection.createStatement().execute(...)`. The
/// compiler already emits both calls and the outer call's exact receiver text,
/// so preserve that relationship as another finite type alias. Provider and
/// method identities still come exclusively from declared return types or
/// rulepack typing; this helper owns no library/API vocabulary.
///
/// The receiver's exact Tree-sitter span identifies the nested call that
/// produced it, so argument-bearing factories require no source-text
/// reconstruction and work under the same fail-closed identity contract.
#[allow(clippy::too_many_arguments)] // Exact call typing joins receiver, assignment, import, and workspace identity evidence.
fn synth_exact_call_expression_type_aliases(
    calls: &[CallFact],
    call_receivers: &[bonsai_lang_api::CallReceiverFact],
    factory: &RulepackTyping,
    language: &str,
    alias_map: &std::collections::HashMap<String, AliasTarget>,
    compiler_imports: Option<&bonsai_lang_api::ImportIndex>,
    caller: Option<&Decl>,
    workspace_context: Option<&WorkspaceCallIdentityContext<'_>>,
) -> Vec<TypeAliasBinding> {
    let specs = factory.specs_for(language).unwrap_or_default();
    if calls.is_empty() || call_receivers.is_empty() {
        return Vec::new();
    }

    let mut out = Vec::new();
    for outer_call in calls {
        let Some(expression) = outer_call.receiver.as_deref().map(str::trim) else {
            continue;
        };
        let Some(receiver_fact) =
            bonsai_lang_api::call_receiver_fact_for_span(call_receivers, outer_call.span)
        else {
            continue;
        };
        // The frontend proves that the whole receiver expression is a call.
        // Select the call whose compiler callee span begins at that exact
        // receiver node and is contained by it. Nested argument calls begin
        // later; the maximal end chooses the complete callee for chained
        // qualifier spellings without interpreting punctuation or names.
        if !receiver_fact
            .value_flow
            .call_sites
            .contains(&receiver_fact.receiver_span)
        {
            continue;
        }
        let Some(call) = calls
            .iter()
            .filter(|call| {
                call.span.file == receiver_fact.receiver_span.file
                    && call.span.start == receiver_fact.receiver_span.start
                    && call.span.end <= receiver_fact.receiver_span.end
            })
            .max_by_key(|call| call.span.end)
        else {
            continue;
        };

        let mut candidate_types = Vec::new();
        if let Some(context) = workspace_context {
            if let Some(type_name) = workspace_call_return_type(context, &call.callee, call.span, alias_map) {
                push_unique_string(&mut candidate_types, type_name);
            }
        }
        for spec in specs {
            if !typing_imports_allow(&spec.required_imports, compiler_imports) {
                continue;
            }
            if let Some(origin) = spec.binding_origin {
                let Some(caller) = caller else {
                    continue;
                };
                if !call_binding_origin_is_valid(
                    origin,
                    workspace_context
                        .and_then(|context| context.ws.db().adapter_for(caller.name_span.file))
                        .is_some_and(|adapter| adapter.capabilities().bare_call_constructor_syntax),
                    caller,
                    None,
                    workspace_context,
                    call,
                    alias_map,
                    &spec.required_imports,
                    compiler_imports,
                ) {
                    continue;
                }
            }
            if !factory_spec_matches_call(&call.callee, call.receiver.as_deref(), spec, alias_map) {
                continue;
            }
            if spec.kind == MatchKind::New {
                let Some(workspace_context) = workspace_context else {
                    continue;
                };
                if workspace_call_resolves_as_constructor(
                    workspace_context,
                    &call.callee,
                    call.span,
                    alias_map,
                ) == Some(false)
                {
                    continue;
                }
            }
            push_unique_string(&mut candidate_types, spec.type_name.clone());
        }

        // Multiple independently valid return contracts make the expression
        // ambiguous. Failing closed prevents an external model from choosing
        // one arbitrarily and mirrors workspace-call return typing.
        if candidate_types.len() == 1 {
            out.push(TypeAliasBinding {
                name: expression.to_string(),
                type_name: candidate_types.pop().expect("single candidate type"),
            });
        }
    }
    out.sort_by(|a, b| (&a.name, &a.type_name).cmp(&(&b.name, &b.type_name)));
    out.dedup();
    out
}

fn typing_imports_allow(
    required: &[String],
    compiler_imports: Option<&bonsai_lang_api::ImportIndex>,
) -> bool {
    if required.is_empty() {
        return true;
    }
    let Some(imports) = compiler_imports else {
        return false;
    };
    imports.imports.iter().any(|import| {
        required
            .iter()
            .any(|wanted| import_module_matches(&import.module, wanted))
    })
}

fn import_module_matches(actual: &str, wanted: &str) -> bool {
    actual == wanted
        || actual.strip_prefix(wanted).is_some_and(|suffix| {
            suffix
                .chars()
                .next()
                .is_some_and(|ch| matches!(ch, '.' | ':' | '/'))
        })
        || wanted.strip_prefix(actual).is_some_and(|suffix| {
            suffix
                .chars()
                .next()
                .is_some_and(|ch| matches!(ch, '.' | ':' | '/'))
        })
}

fn callback_type_target_matches(
    actual: &str,
    target: &RuleTarget,
    alias_map: &std::collections::HashMap<String, AliasTarget>,
) -> bool {
    rule_target_matches_call_with_aliases(actual, &[], target, alias_map)
}

fn push_callback_param_aliases(
    out: &mut Vec<TypeAliasBinding>,
    params: &[String],
    param_types: &[Vec<String>],
) {
    for (param, type_aliases) in params.iter().zip(param_types) {
        for type_name in type_aliases {
            if type_name.trim().is_empty() {
                continue;
            }
            let binding = TypeAliasBinding {
                name: param.clone(),
                type_name: type_name.clone(),
            };
            if !out.contains(&binding) {
                out.push(binding);
            }
        }
    }
}

/// Synthesize the same rulepack-owned callback parameter aliases used by the
/// full body matcher from the independently decodable compiler syntax header.
/// This keeps broad planning monotone: a rule that can match after exact body
/// hydration cannot be rejected merely because its external callback
/// signature is absent from source syntax.
fn synth_callback_param_type_aliases_from_header(
    syntax: &CompilerSyntaxHeader,
    typing: &RulepackTyping,
    language: &str,
    alias_map: &std::collections::HashMap<String, AliasTarget>,
    compiler_imports: Option<&bonsai_lang_api::ImportIndex>,
) -> Vec<TypeAliasBinding> {
    let Some(specs) = typing.callback_specs_for(language) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for spec in specs {
        if !typing_imports_allow(&spec.required_imports, compiler_imports) {
            continue;
        }
        match spec.kind {
            MatchKind::Call => {
                let Some(argument_index) = spec.callback_arg_index else {
                    continue;
                };
                for callback in syntax.callback_arguments.iter().filter(|callback| {
                    callback.argument_index == argument_index
                        && callback.field_path == spec.callback_field_path
                        && rule_target_matches_call_with_aliases(
                            &callback.call_name,
                            &callback.call_receiver_types,
                            &spec.target,
                            alias_map,
                        )
                }) {
                    push_callback_param_aliases(&mut out, &callback.params, &spec.param_types);
                }
            }
            MatchKind::Type => {
                for callback in syntax.typed_callables.iter().filter(|callback| {
                    callback
                        .type_names
                        .iter()
                        .any(|type_name| callback_type_target_matches(type_name, &spec.target, alias_map))
                }) {
                    push_callback_param_aliases(&mut out, &callback.params, &spec.param_types);
                }
            }
            _ => {}
        }
    }
    out
}

/// Synthesize external callback parameter types from rulepack declarations
/// and compiler-owned callback relationships. No provider callable or type
/// spelling is interpreted by the engine.
#[allow(clippy::too_many_arguments)] // Callback typing requires enclosing declarations, call facts, aliases, imports, and rule constraints.
fn synth_callback_param_type_aliases(
    decl: &Decl,
    file_decls: &[Decl],
    decl_calls: &[CallFact],
    file_calls: &[CallFact],
    call_argument_values: &[bonsai_lang_api::CallArgumentValueFact],
    typing: &RulepackTyping,
    language: &str,
    alias_map: &std::collections::HashMap<String, AliasTarget>,
    compiler_imports: Option<&bonsai_lang_api::ImportIndex>,
    workspace_context: Option<&WorkspaceCallIdentityContext<'_>>,
    bare_type_is_callable: bool,
) -> Vec<TypeAliasBinding> {
    let Some(specs) = typing.callback_specs_for(language) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for spec in specs {
        if !typing_imports_allow(&spec.required_imports, compiler_imports) {
            continue;
        }
        match spec.kind {
            MatchKind::Call => {
                let Some(argument_index) = spec.callback_arg_index else {
                    continue;
                };
                let binding_origin_allows = |call: &CallFact| {
                    spec.binding_origin.is_none_or(|origin| {
                        call_binding_origin_is_valid(
                            origin,
                            bare_type_is_callable,
                            decl,
                            Some(file_decls),
                            workspace_context,
                            call,
                            alias_map,
                            &spec.required_imports,
                            compiler_imports,
                        )
                    })
                };
                if !spec.callback_field_path.is_empty() {
                    for callback in call_argument_values.iter().filter_map(|fact| {
                        let field = fact
                            .inline_callback_fields
                            .iter()
                            .find(|field| field.path == spec.callback_field_path)?;
                        let call = decl_calls
                            .iter()
                            .find(|call| {
                                call.span == fact.call_span
                                    && rule_target_matches_call_with_aliases(
                                        &call.callee,
                                        &call.receiver_types,
                                        &spec.target,
                                        alias_map,
                                    )
                            })
                            .or_else(|| {
                                (field.callback_span == decl.span).then(|| {
                                    file_calls.iter().find(|call| {
                                        call.span == fact.call_span
                                            && rule_target_matches_call_with_aliases(
                                                &call.callee,
                                                &call.receiver_types,
                                                &spec.target,
                                                alias_map,
                                            )
                                    })
                                })?
                            })?;
                        if !binding_origin_allows(call) {
                            return None;
                        }
                        (fact.argument_index == argument_index).then_some((call, field))
                    }) {
                        let (_, field) = callback;
                        push_callback_param_aliases(&mut out, &field.params, &spec.param_types);
                    }
                    continue;
                }
                for callback in call_argument_values
                    .iter()
                    .filter(|fact| fact.argument_index == argument_index)
                {
                    let provider_in_decl = decl_calls.iter().find(|call| {
                        call.span == callback.call_span
                            && binding_origin_allows(call)
                            && rule_target_matches_call_with_aliases(
                                &call.callee,
                                &call.receiver_types,
                                &spec.target,
                                alias_map,
                            )
                    });
                    let provider_for_callback_decl = (callback.inline_callback_span == Some(decl.span))
                        .then(|| {
                            file_calls.iter().find(|call| {
                                call.span == callback.call_span
                                    && binding_origin_allows(call)
                                    && rule_target_matches_call_with_aliases(
                                        &call.callee,
                                        &call.receiver_types,
                                        &spec.target,
                                        alias_map,
                                    )
                            })
                        })
                        .flatten();
                    if provider_in_decl.is_none() && provider_for_callback_decl.is_none() {
                        continue;
                    }
                    push_callback_param_aliases(
                        &mut out,
                        &callback.inline_callback_params,
                        &spec.param_types,
                    );
                }
            }
            MatchKind::Type => {
                let callable_type_matches = decl
                    .type_aliases
                    .iter()
                    .filter(|alias| alias.name == decl.name)
                    .any(|alias| callback_type_target_matches(&alias.type_name, &spec.target, alias_map));
                if callable_type_matches {
                    push_callback_param_aliases(&mut out, &decl.params, &spec.param_types);
                }
            }
            _ => {}
        }
    }
    out
}

/// Compile rulepack lifecycle transfers against the exact call facts for one
/// declaration. This is deliberately part of matcher fact construction: the
/// adapter contributes syntax and receiver/type evidence, while typing rules
/// contribute external API meaning.
fn synth_lifecycle_transitions(
    calls: &[CallFact],
    typing: &RulepackTyping,
    language: &str,
    alias_map: &std::collections::HashMap<String, AliasTarget>,
    compiler_imports: Option<&bonsai_lang_api::ImportIndex>,
) -> Vec<(Span, String, String)> {
    let Some(specs) = typing.lifecycle_specs_for(language) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for call in calls {
        for spec in specs {
            if !typing_imports_allow(&spec.required_imports, compiler_imports)
                || !rule_target_matches_call_with_aliases(
                    &call.callee,
                    &call.receiver_types,
                    &spec.target,
                    alias_map,
                )
            {
                continue;
            }
            let raw_binding = match spec.binding {
                LifecycleBindingTarget::Receiver => call
                    .receiver
                    .as_deref()
                    .or_else(|| bonsai_common::qualified_name_owner(&call.callee))
                    .map(str::to_string),
                LifecycleBindingTarget::Argument { index } => usize::try_from(index)
                    .ok()
                    .and_then(|index| call.args.get(index))
                    .and_then(call_arg_single_value_identity),
            };
            let Some(binding) = raw_binding.as_deref().and_then(canonical_lifecycle_binding) else {
                continue;
            };
            out.push((call.span, binding, spec.state.clone()));
        }
    }
    out.sort_by(|left, right| {
        (left.0.start, left.0.end, left.1.as_str(), left.2.as_str()).cmp(&(
            right.0.start,
            right.0.end,
            right.1.as_str(),
            right.2.as_str(),
        ))
    });
    out.dedup();
    out
}

/// Canonicalize an adapter-proven place without collapsing field paths. A
/// full place (`self.stream`) must not alias an unrelated local (`stream`).
fn canonical_lifecycle_binding(raw: &str) -> Option<String> {
    let binding = bonsai_common::trim_leading_name_punctuation(raw.trim()).trim();
    (!binding.is_empty()).then(|| binding.to_string())
}

type FileDeclFactsKey = (
    u64,
    FileId,
    u64,
    u64,
    u64,
    DeclFactRequirements,
    Option<bonsai_index::GlobalIndexIdentity>,
    Option<Arc<[Span]>>,
);
static DECL_FACTS_CACHE: std::sync::LazyLock<MatcherFactCache<FileDeclFactsKey, FileDeclFactsBundle>> =
    std::sync::LazyLock::new(|| MatcherFactCache::new(matcher_fact_cache_budget_share(7, 8)));

fn prepare_matcher_fact_caches_for_broad_scan() {
    FILE_PACKAGE_SET_CACHE.set_retained_budget(matcher_fact_cache_budget_share(3, 32));
    LANGUAGE_IMPORT_PACKAGE_CONTEXT_CACHE.set_retained_budget(matcher_fact_cache_budget_share(1, 16));
    EXACT_MODULE_FILE_INDEX_CACHE.set_retained_budget(matcher_fact_cache_budget_share(1, 8));
    MODULE_EXPORT_TYPE_CACHE.set_retained_budget(matcher_fact_cache_budget_share(1, 8));
    DECL_FACTS_CACHE.set_retained_budget(matcher_fact_cache_budget_share(7, 8));
}

/// End broad matcher ownership before opening a workspace-sized semantic
/// graph. These caches contain only deterministic projections of compiler
/// facts; clearing them changes reuse, never matching or taint semantics.
pub(crate) fn release_matcher_fact_caches() {
    FILE_PACKAGE_SET_CACHE.clear_retained();
    LANGUAGE_IMPORT_PACKAGE_CONTEXT_CACHE.clear_retained();
    EXACT_MODULE_FILE_INDEX_CACHE.clear_retained();
    MODULE_EXPORT_TYPE_CACHE.clear_retained();
    DECL_FACTS_CACHE.clear_retained();
    FILE_PACKAGE_SET_CACHE.set_retained_budget(point_matcher_fact_cache_budget_share(3, 32));
    LANGUAGE_IMPORT_PACKAGE_CONTEXT_CACHE.set_retained_budget(point_matcher_fact_cache_budget_share(1, 16));
    EXACT_MODULE_FILE_INDEX_CACHE.set_retained_budget(point_matcher_fact_cache_budget_share(1, 8));
    MODULE_EXPORT_TYPE_CACHE.set_retained_budget(point_matcher_fact_cache_budget_share(1, 8));
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

#[derive(Clone)]
struct DeclMatchFactsRequest<'a> {
    factory: &'a RulepackTyping,
    requirements: DeclFactRequirements,
    retention: FactRetention,
    compiler_imports: Option<&'a bonsai_lang_api::ImportIndex>,
    global_headers: Option<&'a GlobalIndex>,
    /// If present, derive return/factory/callback receiver types only for
    /// these declarations. Module export typing remains complete because any
    /// selected declaration may consume it. `None` requests the historical
    /// complete-file projection used by point queries.
    call_result_type_decls: Option<Arc<[Span]>>,
}

/// Return the per-decl matcher fact bundle for `file`. Builds the
/// bundle on miss; cached on
/// `(vfs, file, version, text_hash, factory_fp, requirements, headers)` so
/// source edits, rulepack typing, requested evidence, and symbol remapping
/// naturally invalidate. `factory_fp` is 0 when the pack declares no
/// call-result, constructor, callback, or lifecycle typing.
fn decl_match_facts_for_retention(
    ws: &Workspace,
    file: FileId,
    file_index: Option<&DeclIndex>,
    request: DeclMatchFactsRequest<'_>,
) -> Arc<FileDeclFactsBundle> {
    let factory = request.factory;
    let requirements = request.requirements;
    let retention = request.retention;
    let global_headers = request.global_headers;
    let call_result_type_decls = request.call_result_type_decls.clone();
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
        requirements,
        global_headers.map(GlobalIndex::identity),
        call_result_type_decls,
    );
    DECL_FACTS_CACHE.get_or_insert_with(
        key,
        || {
            if let Some(index) = file_index {
                build_decl_match_facts_bundle(ws, file, index, request)
            } else {
                match retention {
                    FactRetention::Cached => ws
                        .db()
                        .decl_index(file)
                        .map(|index| build_decl_match_facts_bundle(ws, file, index.as_ref(), request)),
                    FactRetention::Transient => ws
                        .db()
                        .decl_index_uncached(file)
                        .map(|index| build_decl_match_facts_bundle(ws, file, &index, request)),
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
    request: DeclMatchFactsRequest<'_>,
) -> Arc<FileDeclFactsBundle> {
    let DeclMatchFactsRequest {
        factory,
        requirements,
        retention,
        compiler_imports,
        global_headers,
        call_result_type_decls,
    } = request;
    let import_aliases = file_alias_map_with_compiler_imports(ws, file, retention, compiler_imports);
    let compiler_import_aliases = compiler_imports.map(bonsai_lang_api::alias_map_from_imports);
    let source_text = requirements
        .contains(DeclFactRequirements::ASSIGNMENT_TEXTS)
        .then(|| ws.db().vfs().snapshot(file).ok().map(|snapshot| snapshot.text))
        .flatten();
    // File language scopes rulepack typing (a Python `cursor` factory must
    // not type `.cursor()` in a JS file). Skipped entirely when the pack
    // declares no call-result, constructor, or callback typing.
    let file_language = (!factory.is_empty()
        && (requirements.contains(DeclFactRequirements::CALL_RESULT_TYPES)
            || requirements.contains(DeclFactRequirements::LIFECYCLE)))
    .then(|| {
        ws.db()
            .adapter_for(file)
            .map(|a| a.language_id().as_str().to_string())
    })
    .flatten();
    let module_decl = file_index
        .defs
        .iter()
        .find(|decl| decl.name == bonsai_lang_api::MODULE_DECL_NAME);
    let mut module_type_aliases: Vec<TypeAliasBinding> = module_decl
        .into_iter()
        .flat_map(|decl| decl.type_aliases.iter().cloned())
        .collect();
    if requirements.contains(DeclFactRequirements::CALL_RESULT_TYPES) {
        if let Some(global) = global_headers {
            for alias in imported_module_value_type_aliases(
                ws,
                global,
                file_index,
                factory,
                file_language.as_deref(),
                compiler_imports,
            ) {
                if !module_type_aliases.contains(&alias) {
                    module_type_aliases.push(alias);
                }
            }
        }
    }
    if requirements.contains(DeclFactRequirements::CALL_RESULT_TYPES) {
        if let Some(module_decl) = module_decl {
            let mut module_alias_map = import_aliases.clone();
            extend_alias_map_with_declared_types(&mut module_alias_map, &module_type_aliases);
            bonsai_lang_api::extend_alias_map_with_flow_events(
                &mut module_alias_map,
                &module_decl.flow_events,
            );
            let module_context = global_headers.map(|global| WorkspaceCallIdentityContext {
                ws,
                global,
                caller: module_decl,
            });
            let mut module_calls = collect_calls(&module_decl.flow_events);
            enrich_assignment_call_fact_receivers(&mut module_calls, &file_index.assignment_values);
            enrich_call_fact_receiver_types(&mut module_calls, &module_type_aliases);
            if let Some(import_aliases) = compiler_import_aliases.as_ref() {
                enrich_call_fact_receiver_import_types(&mut module_calls, import_aliases);
            }
            loop {
                let prior_len = module_type_aliases.len();
                if let Some(context) = module_context.as_ref() {
                    for alias in synth_workspace_call_result_type_aliases(
                        &module_decl.flow_events,
                        context,
                        &module_alias_map,
                        factory,
                        file_language.as_deref(),
                    ) {
                        if !module_type_aliases.contains(&alias) {
                            module_type_aliases.push(alias);
                        }
                    }
                }
                if let Some(lang) = file_language.as_deref() {
                    for alias in synth_factory_type_aliases(
                        &module_decl.flow_events,
                        &file_index.assignment_values,
                        factory,
                        lang,
                        &module_alias_map,
                        compiler_imports,
                        Some(module_decl),
                        module_context.as_ref(),
                    ) {
                        if !module_type_aliases.contains(&alias) {
                            module_type_aliases.push(alias);
                        }
                    }
                }
                for alias in synth_exact_call_expression_type_aliases(
                    &module_calls,
                    &file_index.call_receivers,
                    factory,
                    file_language.as_deref().unwrap_or_default(),
                    &module_alias_map,
                    compiler_imports,
                    Some(module_decl),
                    module_context.as_ref(),
                ) {
                    if !module_type_aliases.contains(&alias) {
                        module_type_aliases.push(alias);
                    }
                }
                if module_type_aliases.len() == prior_len {
                    break;
                }
                extend_alias_map_with_declared_types(
                    &mut module_alias_map,
                    &module_type_aliases[prior_len..],
                );
                enrich_call_fact_receiver_types(&mut module_calls, &module_type_aliases[prior_len..]);
                if let Some(import_aliases) = compiler_import_aliases.as_ref() {
                    enrich_call_fact_receiver_import_types(&mut module_calls, import_aliases);
                }
            }
        }
    }
    let assignment_values = requirements
        .contains(DeclFactRequirements::ASSIGNMENT_TEXTS)
        .then(|| AssignmentValueIndex::new(&file_index.assignment_values));
    let file_calls = file_language
        .as_deref()
        .filter(|_| requirements.contains(DeclFactRequirements::CALL_RESULT_TYPES))
        .and_then(|language| factory.callback_specs_for(language))
        .filter(|specs| !specs.is_empty())
        .map(|_| {
            let mut calls = Vec::new();
            for owner in &file_index.defs {
                let mut owner_calls = collect_calls(&owner.flow_events);
                // Callback declarations are indexed independently from the
                // enclosing provider call. Preserve the provider call's own
                // compiler type environment before making it visible to the
                // callback: testing a nested call against the callback's
                // aliases loses exact parameter/receiver typing from the
                // enclosing declaration (`router: Router`).
                enrich_call_fact_receiver_types(&mut owner_calls, &module_type_aliases);
                enrich_call_fact_receiver_types(&mut owner_calls, &owner.type_aliases);
                if let Some(import_aliases) = compiler_import_aliases.as_ref() {
                    enrich_call_fact_receiver_import_types(&mut owner_calls, import_aliases);
                }
                calls.extend(owner_calls);
            }
            calls
        })
        .unwrap_or_default();
    let mut by_decl_span: AHashMap<Span, Arc<DeclMatchFacts>> = AHashMap::new();
    for decl in &file_index.defs {
        let derive_call_result_types = requirements.contains(DeclFactRequirements::CALL_RESULT_TYPES)
            && call_result_type_decls
                .as_ref()
                .is_none_or(|selected| selected.binary_search(&decl.span).is_ok());
        let mut alias_map = import_aliases.clone();
        extend_alias_map_with_declared_types(&mut alias_map, &module_type_aliases);
        let class_field_type_aliases = if derive_call_result_types {
            file_language.as_deref().map_or_else(Vec::new, |language| {
                synth_class_field_type_aliases(
                    ws,
                    file_index,
                    decl,
                    factory,
                    language,
                    &alias_map,
                    compiler_imports,
                    global_headers,
                )
            })
        } else {
            Vec::new()
        };
        extend_alias_map_with_declared_types(&mut alias_map, &class_field_type_aliases);
        // Parameter and local bindings are applied after class-state aliases
        // so lexical values with the same concise name shadow the implicit
        // receiver field.
        extend_alias_map_with_declared_types(&mut alias_map, &decl.type_aliases);
        bonsai_lang_api::extend_alias_map_with_flow_events(&mut alias_map, &decl.flow_events);
        let assignment_map = assignment_values
            .as_ref()
            .map_or_else(AHashMap::new, |assignment_values| {
                collect_assignment_texts(&decl.flow_events, assignment_values, source_text.as_deref())
            });
        let workspace_context = global_headers.map(|global| WorkspaceCallIdentityContext {
            ws,
            global,
            caller: decl,
        });
        let mut calls = collect_calls(&decl.flow_events);
        enrich_assignment_call_fact_receivers(&mut calls, &file_index.assignment_values);
        enrich_call_fact_receiver_types(&mut calls, &module_type_aliases);
        enrich_call_fact_receiver_types(&mut calls, &decl.type_aliases);
        let mut derived_type_aliases = class_field_type_aliases;
        if derive_call_result_types {
            // First-party declared return types and rule-declared external
            // return types form one finite monotone relation over compiler
            // assignment targets. Derive the exact fixed point without an
            // iteration cap so mixed chains remain exact across locals.
            loop {
                let prior_len = derived_type_aliases.len();
                if let Some(context) = workspace_context.as_ref() {
                    for alias in synth_workspace_call_result_type_aliases(
                        &decl.flow_events,
                        context,
                        &alias_map,
                        factory,
                        file_language.as_deref(),
                    ) {
                        if !derived_type_aliases.contains(&alias) {
                            derived_type_aliases.push(alias);
                        }
                    }
                }
                if let Some(lang) = file_language.as_deref() {
                    for alias in synth_factory_type_aliases(
                        &decl.flow_events,
                        &file_index.assignment_values,
                        factory,
                        lang,
                        &alias_map,
                        compiler_imports,
                        Some(decl),
                        workspace_context.as_ref(),
                    ) {
                        if !derived_type_aliases.contains(&alias) {
                            derived_type_aliases.push(alias);
                        }
                    }
                }
                for alias in synth_exact_call_expression_type_aliases(
                    &calls,
                    &file_index.call_receivers,
                    factory,
                    file_language.as_deref().unwrap_or_default(),
                    &alias_map,
                    compiler_imports,
                    Some(decl),
                    workspace_context.as_ref(),
                ) {
                    if !derived_type_aliases.contains(&alias) {
                        derived_type_aliases.push(alias);
                    }
                }
                if derived_type_aliases.len() == prior_len {
                    break;
                }
                extend_alias_map_with_declared_types(&mut alias_map, &derived_type_aliases[prior_len..]);
            }
        }
        if !derived_type_aliases.is_empty() {
            // Resolved-return and factory-typed locals participate in
            // receiver matching and package candidate chasing.
            enrich_call_fact_receiver_types(&mut calls, &derived_type_aliases);
        }
        if derive_call_result_types {
            if let Some(lang) = file_language.as_deref() {
                let callback_aliases = synth_callback_param_type_aliases(
                    decl,
                    &file_index.defs,
                    &calls,
                    &file_calls,
                    &file_index.call_argument_values,
                    factory,
                    lang,
                    &alias_map,
                    compiler_imports,
                    workspace_context.as_ref(),
                    ws.db()
                        .adapter_for(decl.name_span.file)
                        .is_some_and(|adapter| adapter.capabilities().bare_call_constructor_syntax),
                );
                if !callback_aliases.is_empty() {
                    enrich_call_fact_receiver_types(&mut calls, &callback_aliases);
                    extend_alias_map_with_declared_types(&mut alias_map, &callback_aliases);
                    for alias in callback_aliases {
                        if !derived_type_aliases.contains(&alias) {
                            derived_type_aliases.push(alias);
                        }
                    }
                }
            }
        }
        if let Some(import_aliases) = compiler_import_aliases.as_ref() {
            enrich_call_fact_receiver_import_types(&mut calls, import_aliases);
        }
        let receiver_counts = if requirements.contains(DeclFactRequirements::RECEIVER_COUNTS) {
            receiver_method_call_counts(&calls)
        } else {
            AHashMap::new()
        };
        let decl_decorators = if requirements.contains(DeclFactRequirements::DECORATORS) {
            decl_decorator_names(ws, file, file_index, decl.span, decl.name_span)
        } else {
            Vec::new()
        };
        let alias_chains = if requirements.contains(DeclFactRequirements::ALIAS_CHAINS) {
            collect_must_alias_pairs(&decl.flow_events)
        } else {
            AHashMap::new()
        };
        let runtime_types = if requirements.contains(DeclFactRequirements::RUNTIME_TYPES) {
            collect_runtime_type_narrowings(decl.span, &file_index.runtime_type_narrowings)
        } else {
            Vec::new()
        };
        // Preserve any language-syntax lifecycle facts (for example a future
        // adapter-owned ownership construct), then add external API
        // transitions compiled exclusively from typing rules.
        let lifecycle_transitions = if requirements.contains(DeclFactRequirements::LIFECYCLE) {
            let mut transitions = collect_lifecycle_transitions(&decl.flow_events);
            if let Some(lang) = file_language.as_deref() {
                transitions.extend(synth_lifecycle_transitions(
                    &calls,
                    factory,
                    lang,
                    &alias_map,
                    compiler_imports,
                ));
            }
            transitions.sort_by(|left, right| {
                (left.0.start, left.0.end, left.1.as_str(), left.2.as_str()).cmp(&(
                    right.0.start,
                    right.0.end,
                    right.1.as_str(),
                    right.2.as_str(),
                ))
            });
            transitions.dedup();
            transitions
        } else {
            Vec::new()
        };
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
                derived_type_aliases,
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
        MatchKind::Read | MatchKind::Write | MatchKind::Return | MatchKind::Param | MatchKind::Type => {
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

/// A manifest can support an anchored regex only when its leading compiler
/// callee identity is an explicit qualified path (`cowboy_req:match_qs`,
/// `Package.Type.method`, ...). Stop at the first regex metacharacter; a bare
/// function name or wildcard receiver is not package ownership evidence.
fn regex_has_literal_qualified_prefix(regex: &str) -> bool {
    let rest = regex.trim().strip_prefix('^').unwrap_or(regex);
    let literal = rest
        .split(|ch: char| {
            matches!(
                ch,
                '(' | ')' | '[' | ']' | '{' | '}' | '*' | '+' | '?' | '|' | '$' | '\\'
            )
        })
        .next()
        .unwrap_or_default();
    bonsai_common::qualified_name_segments(literal).len() >= 2
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
    alias_map.get(bare)?;
    let expanded = expand_callee_alias(callee, alias_map)?;
    if callee_matches_with_receiver_types(&expanded, receiver_types, name, attribute, regex) {
        return Some(expanded);
    }
    None
}

fn scan_refs_batch(
    ctx: &FileScanContext<'_, '_>,
    rules: &PreparedRuleBatch<'_, '_>,
    want_kind: RefKind,
    _include_workspace_package_context: bool,
    factory: &RulepackTyping,
    out: &mut Vec<RuleMatch>,
) {
    let ws = ctx.ws;
    let file = ctx.file;
    let file_index = ctx.file_index;
    let retention = ctx.retention;
    let decls = file_index.defs.as_slice();
    let file_packages = ctx.package_evidence;
    let alias_map = file_alias_map_with_compiler_imports(ws, file, retention, ctx.file_imports);
    let requirements = DeclFactRequirements::for_rules(rules.read_rules.iter().copied());
    let derived_receiver_decls = if requirements.contains(DeclFactRequirements::CALL_RESULT_TYPES) {
        read_batch_derived_receiver_decls(ctx, rules, want_kind, &alias_map)
    } else {
        Arc::<[Span]>::from([])
    };
    let derived_types = (!derived_receiver_decls.is_empty()).then(|| {
        decl_match_facts_for_retention(
            ws,
            file,
            Some(file_index),
            DeclMatchFactsRequest {
                factory,
                requirements,
                retention,
                compiler_imports: ctx.file_imports,
                global_headers: ctx.global_headers,
                call_result_type_decls: Some(derived_receiver_decls),
            },
        )
    });
    let mut candidate_rules = Vec::new();
    for r in &file_index.refs {
        if r.kind != want_kind {
            continue;
        }
        let enclosing_decl = innermost_decl_for_span(decls, r.span);
        candidate_rules.clear();
        push_read_candidate_rules(&mut candidate_rules, rules, &r.name, &alias_map);
        for prepared in candidate_rules.iter().copied() {
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
            let mut receiver_types = enclosing_decl.map_or_else(Vec::new, |decl| {
                exact_declared_receiver_types_for_match_base(decl, &r.name, ctx.file_imports)
            });
            let derived_type_aliases = enclosing_decl
                .and_then(|decl| derived_types.as_ref()?.by_decl_span.get(&decl.span))
                .map_or(&[][..], |facts| facts.derived_type_aliases.as_slice());
            append_derived_receiver_types_for_match_base(&mut receiver_types, derived_type_aliases, &r.name);
            receiver_types = expanded_receiver_types(&receiver_types, ctx.receiver_base_map);
            if !base_receiver_type_allows(
                prepared,
                enclosing_decl,
                &r.name,
                &receiver_types,
                derived_type_aliases,
            ) || external_receiver_type_is_workspace_shadow_at(
                prepared,
                &receiver_types,
                &file_index.defs,
                ctx.file_imports,
                Some(&r.name),
            ) || !read_receiver_constraints_allow(prepared, &receiver_types)
            {
                continue;
            }
            // Receiver-agnostic read regexes (`^[A-Za-z_]\w*\.body$`)
            // would otherwise fire on any `<ident>.body` shape across
            // every workspace file — koa's request_body matching
            // every aws-lambda example is the canonical regression.
            // The package-signal gate is the same one that
            // call-shaped rules use; reads need it just as much.
            if !prepared.call_or_source_context_allows(
                &r.name,
                &[],
                &alias_map,
                file_packages,
                file_index,
                enclosing_decl,
            ) {
                continue;
            }
            if prepared_reference_binding_origin_is_invalid(
                ws,
                file,
                prepared,
                enclosing_decl,
                &file_index.defs,
                &r.name,
                r.span,
                &alias_map,
                ctx.file_imports,
            ) {
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

/// Identify only declarations where a read rule can gain its required
/// receiver type from exact call-result/factory propagation. Direct compiler
/// receiver/import types settle the common case without deriving every
/// callable's secondary type fixed point. This is scheduling only: selected
/// declarations still use the canonical fact builder and unselected reads
/// have already received a final direct-type verdict.
fn read_batch_derived_receiver_decls(
    ctx: &FileScanContext<'_, '_>,
    rules: &PreparedRuleBatch<'_, '_>,
    want_kind: RefKind,
    alias_map: &std::collections::HashMap<String, AliasTarget>,
) -> Arc<[Span]> {
    let file_index = ctx.file_index;
    let derivable = DerivedReceiverCandidates::from_context(ctx, &rules.factory);
    let mut selected = Vec::new();
    let mut candidate_rules = Vec::new();
    for reference in file_index
        .refs
        .iter()
        .filter(|reference| reference.kind == want_kind)
    {
        let Some(decl) = innermost_decl_for_span(&file_index.defs, reference.span) else {
            continue;
        };
        candidate_rules.clear();
        push_read_candidate_rules(&mut candidate_rules, rules, &reference.name, alias_map);
        for prepared in candidate_rules.iter().copied() {
            let target = prepared.rule.match_spec.target.as_ref();
            if !decl_target_context_allows(file_index, Some(decl), target, None)
                || !callee_matches(
                    &reference.name,
                    prepared.name,
                    prepared.attribute,
                    prepared.regex.as_ref(),
                )
                || !prepared.base_name_allows(&reference.name)
                || !base_param_index_allows(prepared, Some(decl), &reference.name)
            {
                continue;
            }
            let direct_types = expanded_receiver_types(
                &exact_declared_receiver_types_for_match_base(decl, &reference.name, ctx.file_imports),
                ctx.receiver_base_map,
            );
            let receiver = match_base_name(&reference.name).unwrap_or(reference.name.as_str());
            if read_receiver_derivation_needed(prepared, &direct_types)
                && derivable.place_can_gain_type(decl, receiver, reference.span)
            {
                selected.push(decl.span);
                break;
            }
        }
    }
    selected.sort_unstable();
    selected.dedup();
    Arc::from(selected)
}

fn scan_flow_reads_batch(
    ctx: &FileScanContext<'_, '_>,
    rules: &PreparedRuleBatch<'_, '_>,
    _include_workspace_package_context: bool,
    factory: &RulepackTyping,
    out: &mut Vec<RuleMatch>,
) {
    let ws = ctx.ws;
    let file = ctx.file;
    let file_index = ctx.file_index;
    let file_packages = ctx.package_evidence;
    let alias_map = file_alias_map_with_compiler_imports(ws, file, ctx.retention, ctx.file_imports);
    let assignment_values = AssignmentValueIndex::new(&file_index.assignment_values);
    let requirements = DeclFactRequirements::for_rules(rules.read_rules.iter().copied());
    let derived_receiver_decls = if requirements.contains(DeclFactRequirements::CALL_RESULT_TYPES) {
        flow_read_batch_derived_receiver_decls(ctx, rules, &alias_map)
    } else {
        Arc::<[Span]>::from([])
    };
    let derived_types = (!derived_receiver_decls.is_empty()).then(|| {
        decl_match_facts_for_retention(
            ws,
            file,
            Some(file_index),
            DeclMatchFactsRequest {
                factory,
                requirements,
                retention: ctx.retention,
                compiler_imports: ctx.file_imports,
                global_headers: ctx.global_headers,
                call_result_type_decls: Some(derived_receiver_decls),
            },
        )
    });
    for decl in &file_index.defs {
        let derived_type_aliases = derived_types
            .as_ref()
            .and_then(|bundle| bundle.by_decl_span.get(&decl.span))
            .map_or(&[][..], |facts| facts.derived_type_aliases.as_slice());
        let mut reads = Vec::new();
        collect_flow_read_sites(
            &decl.flow_events,
            &file_index.assignment_values,
            &file_index.call_receivers,
            &mut reads,
        );
        let mut candidate_rules = Vec::new();
        for (span, tokens) in reads {
            candidate_rules.clear();
            for token in &tokens {
                push_read_candidate_rules(&mut candidate_rules, rules, token, &alias_map);
            }
            for prepared in candidate_rules.iter().copied() {
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
                let mut receiver_types =
                    exact_declared_receiver_types_for_match_base(decl, &match_text, ctx.file_imports);
                append_derived_receiver_types_for_match_base(
                    &mut receiver_types,
                    derived_type_aliases,
                    &match_text,
                );
                receiver_types = expanded_receiver_types(&receiver_types, ctx.receiver_base_map);
                if !base_receiver_type_allows(
                    prepared,
                    Some(decl),
                    &match_text,
                    &receiver_types,
                    derived_type_aliases,
                ) || external_receiver_type_is_workspace_shadow_at(
                    prepared,
                    &receiver_types,
                    &file_index.defs,
                    ctx.file_imports,
                    Some(&match_text),
                ) || !read_receiver_constraints_allow(prepared, &receiver_types)
                {
                    continue;
                }
                // Same package-signal gate that `scan_refs_batch`
                // applies; without it a receiver-agnostic read
                // regex would fire on any file regardless of the
                // imports it actually pulls in.
                if !prepared.call_or_source_context_allows(
                    &match_text,
                    &[],
                    &alias_map,
                    file_packages,
                    file_index,
                    Some(decl),
                ) {
                    continue;
                }
                let span = canonical_flow_read_match_span(ws, file, span, &match_text, &assignment_values);
                if prepared_reference_binding_origin_is_invalid(
                    ws,
                    file,
                    prepared,
                    Some(decl),
                    &file_index.defs,
                    &match_text,
                    span,
                    &alias_map,
                    ctx.file_imports,
                ) {
                    continue;
                }
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

fn flow_read_batch_derived_receiver_decls(
    ctx: &FileScanContext<'_, '_>,
    rules: &PreparedRuleBatch<'_, '_>,
    alias_map: &std::collections::HashMap<String, AliasTarget>,
) -> Arc<[Span]> {
    let file_index = ctx.file_index;
    let derivable = DerivedReceiverCandidates::from_context(ctx, &rules.factory);
    let mut selected = Vec::new();
    let mut candidate_rules = Vec::new();
    for decl in &file_index.defs {
        let mut reads = Vec::new();
        collect_flow_read_sites(
            &decl.flow_events,
            &file_index.assignment_values,
            &file_index.call_receivers,
            &mut reads,
        );
        'reads: for (span, tokens) in reads {
            candidate_rules.clear();
            for token in &tokens {
                push_read_candidate_rules(&mut candidate_rules, rules, token, alias_map);
            }
            for prepared in candidate_rules.iter().copied() {
                let target = prepared.rule.match_spec.target.as_ref();
                if !decl_target_context_allows(file_index, Some(decl), target, None) {
                    continue;
                }
                let Some(match_text) = flow_read_rule_match(prepared, &tokens) else {
                    continue;
                };
                if !base_param_index_allows(prepared, Some(decl), &match_text) {
                    continue;
                }
                let direct_types = expanded_receiver_types(
                    &exact_declared_receiver_types_for_match_base(decl, &match_text, ctx.file_imports),
                    ctx.receiver_base_map,
                );
                let receiver = match_base_name(&match_text).unwrap_or(match_text.as_str());
                if read_receiver_derivation_needed(prepared, &direct_types)
                    && derivable.place_can_gain_type(decl, receiver, span)
                {
                    selected.push(decl.span);
                    break 'reads;
                }
            }
        }
    }
    selected.sort_unstable();
    selected.dedup();
    Arc::from(selected)
}

fn flow_read_rule_match(prepared: &PreparedRule<'_>, tokens: &[String]) -> Option<String> {
    if let Some(name) = prepared.name {
        if let Some(token) = tokens.iter().find(|token| {
            if token.as_str() == name {
                return prepared.base_name_allows(token);
            }
            // A typed member-read rule expresses the security/API spelling
            // as the terminal member (`text`, `body`, `messages`) while the
            // adapter emits the exact structured place (`field.text`).  Only
            // admit that terminal form when the rule also requires receiver
            // type evidence; `base_receiver_type_allows` proves the parsed
            // base immediately after this shape match.  Untyped bare-name
            // rules retain their exact-token semantics.
            rule_primary_target(prepared.rule).is_some_and(|target| {
                !target.receiver_type_in.is_empty()
                    && token.rsplit('.').next() == Some(name)
                    && token.contains('.')
                    && prepared.base_name_allows(token)
            })
        }) {
            return Some(token.clone());
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
        .filter(|alias| {
            normalize_leading_call_punctuation(&alias.name) == normalize_leading_call_punctuation(base)
        })
        .any(|alias| receiver_type_matches_wanted(&alias.type_name, &target.receiver_type_in))
    {
        return true;
    }
    let Some(decl) = decl else {
        return false;
    };
    decl.type_aliases
        .iter()
        .filter(|alias| {
            normalize_leading_call_punctuation(&alias.name) == normalize_leading_call_punctuation(base)
        })
        .any(|alias| receiver_type_matches_wanted(&alias.type_name, &target.receiver_type_in))
}

fn exact_declared_receiver_types_for_match_base(
    decl: &Decl,
    match_text: &str,
    compiler_imports: Option<&bonsai_lang_api::ImportIndex>,
) -> Vec<String> {
    let Some(base) = match_base_name(match_text) else {
        return Vec::new();
    };
    let normalized_base = normalize_leading_call_punctuation(base);
    let mut types = decl
        .type_aliases
        .iter()
        .filter(|alias| normalize_leading_call_punctuation(&alias.name) == normalized_base)
        .map(|alias| alias.type_name.clone())
        .collect::<Vec<_>>();
    if let Some(imports) = compiler_imports {
        let import_aliases = bonsai_lang_api::alias_map_from_imports(imports);
        append_import_expanded_type_identities(&mut types, &import_aliases);
        for import in &imports.imports {
            if import.alias.as_deref() == Some(base) {
                types.push(import.module.clone());
            } else if import.alias.is_none() && !import.is_wildcard {
                if bonsai_common::short_qualified_tail(&import.module) == base {
                    types.push(import.module.clone());
                }
            } else if import.alias.is_none() && import.is_wildcard {
                types.push(format!("{}.{}", import.module, base));
            }
        }
    }
    types.sort();
    types.dedup();
    types
}

fn append_derived_receiver_types_for_match_base(
    receiver_types: &mut Vec<String>,
    aliases: &[TypeAliasBinding],
    match_text: &str,
) {
    let Some(base) = match_base_name(match_text) else {
        return;
    };
    let normalized_base = normalize_leading_call_punctuation(base);
    for alias in aliases
        .iter()
        .filter(|alias| normalize_leading_call_punctuation(&alias.name) == normalized_base)
    {
        if !receiver_types.contains(&alias.type_name) {
            receiver_types.push(alias.type_name.clone());
        }
    }
    receiver_types.sort();
    receiver_types.dedup();
}

/// Preserve adapter-emitted type spellings and add only identities proven by
/// the file's exact compiler import map. Nested source types such as
/// `Provider.Builder` therefore retain their raw spelling while also gaining
/// `external.package.Provider.Builder`; local or ambiguous declarations remain
/// visible to the separate workspace-shadow check and fail closed there.
fn append_import_expanded_type_identities(
    types: &mut Vec<String>,
    import_aliases: &std::collections::HashMap<String, AliasTarget>,
) {
    let expanded = types
        .iter()
        .filter_map(|type_name| expand_callee_alias(type_name, import_aliases))
        .collect::<Vec<_>>();
    for type_name in expanded {
        push_unique_string(types, type_name);
    }
}

fn receiver_type_matches_wanted(actual: &str, wanted: &[String]) -> bool {
    wanted
        .iter()
        .any(|want| actual == want || actual.rsplit('.').next() == Some(want.as_str()))
}

/// Reject an external receiver-type claim when compiler identity cannot prove
/// that every matching receiver belongs to the rule-declared provider.
///
/// A module import proves that an external package is available; it does not
/// make a same-named local `struct Client` into that package's `Client`.
/// Qualified adapter types already carry provider identity. They must match a
/// complete provider-qualified rule identity or an exact compiler import whose
/// module is owned by the rule. Simple types pass only when no exact workspace
/// declaration shadows them. Multiple matching but conflicting compiler
/// identities fail closed.
#[cfg(test)]
fn external_receiver_type_is_workspace_shadow(
    prepared: &PreparedRule<'_>,
    receiver_types: &[String],
    file_decls: &[Decl],
    compiler_imports: Option<&bonsai_lang_api::ImportIndex>,
) -> bool {
    external_receiver_type_is_workspace_shadow_at(
        prepared,
        receiver_types,
        file_decls,
        compiler_imports,
        None,
    )
}

fn external_receiver_type_is_workspace_shadow_at(
    prepared: &PreparedRule<'_>,
    receiver_types: &[String],
    file_decls: &[Decl],
    compiler_imports: Option<&bonsai_lang_api::ImportIndex>,
    match_text: Option<&str>,
) -> bool {
    if prepared.rule.imports.is_empty()
        && prepared.rule.packages.is_empty()
        && prepared.rule.modules.is_empty()
    {
        return false;
    }
    // An exact rule-owned static path can carry provider identity without an
    // instance receiver type (`Provider.shared.value`). A same-named
    // workspace type still wins lexical resolution, so reject that path
    // before considering package availability. The rule supplies the owner;
    // shared matching only compares its structured/literal root with compiler
    // declarations.
    if match_text
        .and_then(match_base_name)
        .is_some_and(|base| exact_rule_target_owns_base(prepared.rule, base))
        && match_text
            .and_then(match_base_name)
            .is_some_and(|base| workspace_declares_type_named(file_decls, base))
    {
        return true;
    }
    let expected = rule_receiver_type_expectations(prepared.rule);
    if expected.is_empty() {
        return false;
    }
    let matching = receiver_types
        .iter()
        .filter(|actual| receiver_type_matches_any(std::slice::from_ref(actual), &expected))
        .collect::<Vec<_>>();
    if matching.is_empty() {
        return false;
    }

    matching.into_iter().any(|actual| {
        let segments = bonsai_common::qualified_name_segments(actual);
        if segments.len() > 1 {
            // Import expansion may qualify an unqualified static receiver in
            // the header (`ExternalMode.WEAK` ->
            // `external.config.ExternalMode`) even when a same-named local
            // type wins lexical resolution. Preserve the original compiler
            // match spelling so local declarations shadow only unqualified
            // references; an explicitly qualified source reference remains
            // exact external evidence.
            let terminal = segments.last().copied();
            let unqualified_local_shadow = match_text
                .and_then(match_base_name)
                .map(bonsai_common::qualified_name_segments)
                .is_some_and(|base_segments| {
                    base_segments.len() == 1
                        && base_segments.last().copied() == terminal
                        && file_decls.iter().any(|decl| {
                            matches!(
                                decl.kind,
                                DeclKind::Class
                                    | DeclKind::Struct
                                    | DeclKind::Trait
                                    | DeclKind::Interface
                                    | DeclKind::Enum
                            ) && Some(decl.name.as_str()) == terminal
                        })
                });
            if unqualified_local_shadow {
                return true;
            }
            // A compiler-qualified receiver carries its provider identity.
            // It may satisfy this external rule only through one equally
            // qualified rule-owned identity; a terminal-name match such as
            // `local.Client` against `provider.Client` is not evidence.
            let exact_rule_identity = expected.iter().any(|wanted| {
                let wanted_segments = bonsai_common::qualified_name_segments(wanted);
                wanted_segments.len() > 1
                    && segments.len() >= wanted_segments.len()
                    && segments[segments.len() - wanted_segments.len()..] == wanted_segments
            });
            let exact_rule_provider = prepared
                .rule
                .packages
                .iter()
                .chain(prepared.rule.imports.iter())
                .chain(prepared.rule.modules.iter())
                .any(|signal| {
                    crate::pkg::import_matches_package(actual, signal, &prepared.rule.package_matching)
                });
            if exact_rule_identity || exact_rule_provider {
                return false;
            }
            let qualifier = segments[0];
            let exact_import_owner = compiler_imports.is_some_and(|imports| {
                let candidates = imports
                    .imports
                    .iter()
                    .filter(|import| {
                        let imported_segments = bonsai_common::qualified_name_segments(&import.module);
                        let local_binding = import
                            .alias
                            .as_deref()
                            .or(import.original_name.as_deref())
                            .map(str::to_string)
                            .or_else(|| bonsai_lang_api::module_local_binding(&import.module));
                        local_binding.as_deref() == Some(qualifier)
                            || (!imported_segments.is_empty()
                                && segments.len() >= imported_segments.len()
                                && segments[..imported_segments.len()] == imported_segments)
                    })
                    .collect::<Vec<_>>();
                // Adapters may retain both the namespace import and its
                // exact named-member binding for one source import. Those
                // records are complementary evidence for the same provider,
                // not ambiguous owners (`module` plus `module.Member`). Only
                // distinct imported modules represent conflicting provider
                // identities and must fail closed.
                let providers = candidates
                    .iter()
                    .map(|import| bonsai_common::normalize_qualified_name(&import.module))
                    .collect::<AHashSet<_>>();
                if providers.len() != 1 {
                    return false;
                }
                candidates.into_iter().any(|import| {
                    let identity = import.original_name.as_deref().map_or_else(
                        || import.module.clone(),
                        |original| format!("{}.{original}", import.module),
                    );
                    prepared
                        .rule
                        .packages
                        .iter()
                        .chain(prepared.rule.imports.iter())
                        .chain(prepared.rule.modules.iter())
                        .any(|signal| {
                            crate::pkg::import_matches_package(
                                &import.module,
                                signal,
                                &prepared.rule.package_matching,
                            ) || crate::pkg::import_matches_package(
                                &identity,
                                signal,
                                &prepared.rule.package_matching,
                            )
                        })
                })
            });
            return !exact_import_owner;
        }
        let Some(simple) = segments.last().copied() else {
            return true;
        };
        file_decls.iter().any(|decl| {
            matches!(
                decl.kind,
                DeclKind::Class | DeclKind::Struct | DeclKind::Trait | DeclKind::Interface | DeclKind::Enum
            ) && decl.name == simple
        })
    })
}

fn workspace_declares_type_named(file_decls: &[Decl], name: &str) -> bool {
    file_decls.iter().any(|decl| {
        matches!(
            decl.kind,
            DeclKind::Class | DeclKind::Struct | DeclKind::Trait | DeclKind::Interface | DeclKind::Enum
        ) && decl.name == name
    })
}

fn exact_rule_target_owns_base(rule: &Rule, base: &str) -> bool {
    let Some(target) = rule_primary_target(rule) else {
        return false;
    };
    if target.attribute.as_ref().is_some_and(|attribute| {
        attribute
            .iter()
            .take(attribute.len().saturating_sub(1))
            .flat_map(|part| bonsai_common::qualified_name_segments(part))
            .any(|part| part == base)
    }) {
        return true;
    }
    target.regex.as_deref().and_then(exact_qualified_regex_root) == Some(base)
}

/// Extract the first literal owner from an anchored qualified-path regex.
/// Character classes, groups, and wildcard dots deliberately fail closed;
/// only an identifier followed by an escaped dot or literal namespace
/// separator is provider ownership evidence.
fn exact_qualified_regex_root(regex: &str) -> Option<&str> {
    let regex = regex.trim();
    let regex = regex
        .strip_prefix("(?i)")
        .or_else(|| regex.strip_prefix("(?-i)"))
        .unwrap_or(regex);
    let rest = regex.strip_prefix('^')?;
    let end = rest
        .find(|ch: char| !(ch == '_' || ch == '$' || ch.is_ascii_alphanumeric()))
        .unwrap_or(rest.len());
    let root = rest.get(..end)?;
    if root.is_empty()
        || !root
            .chars()
            .next()
            .is_some_and(|ch| ch == '_' || ch == '$' || ch.is_ascii_alphabetic())
    {
        return None;
    }
    let suffix = rest.get(end..)?;
    (suffix.starts_with("\\.") || suffix.starts_with("::") || suffix.starts_with(':')).then_some(root)
}

fn rule_receiver_type_expectations(rule: &Rule) -> Vec<String> {
    let mut expected = rule_primary_target(rule)
        .into_iter()
        .flat_map(|target| target.receiver_type_in.iter().cloned())
        .collect::<Vec<_>>();
    for constraint in rule.constraints.iter() {
        if let ConstraintKind::ReceiverTypeIn { receiver_type_in } = constraint {
            expected.extend(receiver_type_in.iter().cloned());
        }
    }
    expected.sort();
    expected.dedup();
    expected
}

fn rule_primary_target(rule: &Rule) -> Option<&RuleTarget> {
    match rule.match_spec.kind {
        MatchKind::Call | MatchKind::New | MatchKind::Missing => rule.match_spec.callee.as_ref(),
        MatchKind::Read | MatchKind::Write | MatchKind::Return | MatchKind::Param | MatchKind::Type => {
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

#[derive(Clone, Debug)]
struct ReturnRuleSite {
    span: Span,
    value_kind: Option<AssignValueKind>,
    value_text: Option<String>,
    value_name: Option<String>,
    /// Exact compiler assignment whose value reaches this return on every
    /// fall-through control-flow predecessor. `None` means either no local
    /// definition or multiple possible definitions; matcher rules fail closed
    /// rather than selecting one textual assignment.
    reaching_assignment: Option<Span>,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum ReturnDefinition {
    One(Span),
    Ambiguous,
}

type ReturnDefinitionState = AHashMap<String, ReturnDefinition>;

fn collect_return_rule_sites(events: &[FlowEvent], out: &mut Vec<ReturnRuleSite>) {
    let mut state = ReturnDefinitionState::new();
    let _ = walk_return_rule_sites(events, &mut state, out, false);
}

/// Walk the structured compiler flow in execution order and retain only a
/// unique reaching assignment for identifier-shaped returns.
///
/// The result is deliberately stricter than lexical "latest assignment":
/// branch joins, zero-iteration loops, and exception alternatives merge to
/// `Ambiguous` unless every fall-through path carries the same definition.
/// Nested compiler-declared bindings are restored at scope exit so an inner
/// shadow never supplies the outer return. API and language spellings are not
/// interpreted here.
fn walk_return_rule_sites(
    events: &[FlowEvent],
    state: &mut ReturnDefinitionState,
    out: &mut Vec<ReturnRuleSite>,
    nested_scope: bool,
) -> bool {
    let entry_state = nested_scope.then(|| state.clone());
    let mut declared_here = AHashSet::new();
    for event in events {
        match event {
            FlowEvent::Assign {
                span,
                target,
                declares_new_binding,
                ..
            } => {
                if nested_scope && *declares_new_binding {
                    declared_here.insert(target.clone());
                }
                state.insert(target.clone(), ReturnDefinition::One(*span));
            }
            FlowEvent::AggregateAssign { span, target, .. } => {
                state.insert(target.clone(), ReturnDefinition::One(*span));
            }
            FlowEvent::Return {
                span,
                value_kind,
                value_text,
                value_name,
                ..
            } => {
                let reaching_assignment = value_name.as_deref().and_then(|name| match state.get(name) {
                    Some(ReturnDefinition::One(span)) => Some(*span),
                    Some(ReturnDefinition::Ambiguous) | None => None,
                });
                out.push(ReturnRuleSite {
                    span: *span,
                    value_kind: *value_kind,
                    value_text: value_text.clone(),
                    value_name: value_name.clone(),
                    reaching_assignment,
                });
                return false;
            }
            FlowEvent::Throw { .. } | FlowEvent::Break { .. } | FlowEvent::Continue { .. } => {
                return false;
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                let before = state.clone();
                let mut then_state = before.clone();
                let then_falls = walk_return_rule_sites(then_events, &mut then_state, out, true);
                let mut else_state = before;
                let else_falls = walk_return_rule_sites(else_events, &mut else_state, out, true);
                let fallthrough = [then_falls.then_some(then_state), else_falls.then_some(else_state)]
                    .into_iter()
                    .flatten()
                    .collect::<Vec<_>>();
                if fallthrough.is_empty() {
                    return false;
                }
                *state = merge_return_definition_states(&fallthrough);
            }
            FlowEvent::Loop { body, .. } => {
                let before = state.clone();
                let mut body_state = before.clone();
                let body_falls = walk_return_rule_sites(body, &mut body_state, out, true);
                let paths = if body_falls {
                    vec![before, body_state]
                } else {
                    vec![before]
                };
                *state = merge_return_definition_states(&paths);
            }
            FlowEvent::Using { body, .. } => {
                if !walk_return_rule_sites(body, state, out, true) {
                    return false;
                }
            }
            // Deferred statements run during scope exit, after the returned
            // expression has been selected, so they cannot define the value
            // whose return shape is being matched.
            FlowEvent::Defer { .. } => {}
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                let before = state.clone();
                let mut body_state = before.clone();
                let body_falls = walk_return_rule_sites(body, &mut body_state, out, true);
                let mut catch_state = before.clone();
                let catch_falls = walk_return_rule_sites(catch_events, &mut catch_state, out, true);
                // A catch may begin after any prefix of the try body. Include
                // the entry state as an additional conservative predecessor;
                // any differing assignment therefore fails closed.
                let mut paths = vec![before];
                if body_falls {
                    paths.push(body_state);
                }
                if catch_falls {
                    paths.push(catch_state);
                }
                *state = merge_return_definition_states(&paths);
                if !walk_return_rule_sites(finally_events, state, out, true) {
                    return false;
                }
            }
            _ => {}
        }
    }

    if let Some(entry_state) = entry_state {
        for name in declared_here {
            match entry_state.get(&name).copied() {
                Some(definition) => {
                    state.insert(name, definition);
                }
                None => {
                    state.remove(&name);
                }
            }
        }
    }
    true
}

fn merge_return_definition_states(paths: &[ReturnDefinitionState]) -> ReturnDefinitionState {
    let mut names = AHashSet::new();
    for path in paths {
        names.extend(path.keys().cloned());
    }
    names
        .into_iter()
        .filter_map(|name| {
            let first = paths.first().and_then(|path| path.get(&name)).copied();
            let definition = if paths.iter().all(|path| path.get(&name).copied() == first) {
                first
            } else {
                Some(ReturnDefinition::Ambiguous)
            }?;
            Some((name, definition))
        })
        .collect()
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
/// onto an existing alias map.
///
/// A compiler-proven value type is the binding identity used for member
/// dispatch. It therefore replaces an import alias for the same local. This
/// matters for imported values: `from pool import connection` first creates
/// an import-member alias, while the exporting module can additionally prove
/// that `connection` is a concrete instance. Keeping only the import spelling
/// would discard that stronger fact and prevent exact receiver-return typing
/// on `connection.cursor()`.
///
/// Import/package evidence remains independently available through the
/// compiler import index; replacing this lookup entry does not manufacture or
/// discard dependency evidence.
fn extend_alias_map_with_declared_types(
    alias_map: &mut std::collections::HashMap<String, AliasTarget>,
    aliases: &[TypeAliasBinding],
) {
    for alias in aliases {
        let target = AliasTarget::Type {
            type_name: alias.type_name.clone(),
        };
        alias_map.insert(alias.name.clone(), target.clone());
        // Some adapters preserve a binding sigil in storage places while
        // their call receiver is the same parser-classified identifier
        // without leading punctuation (`$dbh` versus `dbh`). Retain the exact
        // place and also its vocabulary-free identifier identity so declared
        // and rulepack return types can reach the receiver.
        let normalized = normalize_leading_call_punctuation(&alias.name);
        if normalized != alias.name {
            alias_map.insert(normalized.to_string(), target);
        }
    }
}

fn scan_writes_batch(
    ctx: &FileScanContext<'_, '_>,
    rules: &PreparedRuleBatch<'_, '_>,
    out: &mut Vec<RuleMatch>,
) {
    let ws = ctx.ws;
    let file = ctx.file;
    let file_index = ctx.file_index;
    let mode = ctx.mode;
    let taint_view = ctx.taint_view;
    let retention = ctx.retention;
    let file_packages = ctx.package_evidence;
    let nested_ast_values = NestedAstValueIndex::new(&file_index.defs);
    let assignment_values = AssignmentValueIndex::new(&file_index.assignment_values);
    let source_text = ws.db().vfs().snapshot(file).ok().map(|snapshot| snapshot.text);
    let requirements = DeclFactRequirements::for_rules(rules.write_rules.iter().copied());
    let bundle = decl_match_facts_for_retention(
        ws,
        file,
        Some(file_index),
        DeclMatchFactsRequest {
            factory: &rules.factory,
            requirements,
            retention,
            compiler_imports: ctx.file_imports,
            global_headers: ctx.global_headers,
            call_result_type_decls: None,
        },
    );
    for decl in &file_index.defs {
        let Some(facts) = bundle.by_decl_span.get(&decl.span) else {
            continue;
        };
        let writes = collect_writes(&decl.flow_events);
        for mut write in writes {
            write.extend_with_assignment_value(&assignment_values, source_text.as_deref());
            write.extend_with_nested_ast_values(&nested_ast_values);
            let args = [write.argument.clone()];
            let ast_arg_values = [write.ast_values];
            for prepared in &rules.write_rules {
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
                let mut receiver_types =
                    exact_declared_receiver_types_for_match_base(decl, &write.target, ctx.file_imports);
                append_derived_receiver_types_for_match_base(
                    &mut receiver_types,
                    &facts.derived_type_aliases,
                    &write.target,
                );
                if !base_receiver_type_allows(
                    prepared,
                    Some(decl),
                    &write.target,
                    &receiver_types,
                    &facts.derived_type_aliases,
                ) || external_receiver_type_is_workspace_shadow_at(
                    prepared,
                    &receiver_types,
                    &file_index.defs,
                    ctx.file_imports,
                    Some(&write.target),
                ) {
                    continue;
                }
                // Same package-signal gate the call/read scanners use —
                // a receiver-agnostic write target like
                // `^[A-Za-z_$]\w*\.headers$` would otherwise fire on
                // any file regardless of the rule's `packages` list.
                if !prepared.call_context_allows(
                    &write.target,
                    &receiver_types,
                    &facts.alias_map,
                    file_packages,
                ) {
                    continue;
                }
                if prepared_write_binding_origin_is_invalid(
                    ws,
                    file,
                    prepared,
                    decl,
                    &file_index.defs,
                    &write.target,
                    write.span,
                    &facts.alias_map,
                    ctx.file_imports,
                ) {
                    continue;
                }
                if !constraints_pass(ConstraintEval {
                    rule_id: &prepared.rule.id,
                    callee: &write.target,
                    receiver: None,
                    args: &args,
                    receiver_types: &receiver_types,
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
                        string_compositions: &file_index.string_compositions,
                        factory_import_identity: None,
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
    rules: &PreparedRuleBatch<'_, '_>,
    out: &mut Vec<RuleMatch>,
) {
    let ws = ctx.ws;
    let file = ctx.file;
    let file_index = ctx.file_index;
    let mode = ctx.mode;
    let taint_view = ctx.taint_view;
    let retention = ctx.retention;
    let decls = file_index.defs.as_slice();
    let file_packages = ctx.package_evidence;
    let source_text = ws.db().vfs().snapshot(file).ok().map(|snapshot| snapshot.text);
    let requirements = DeclFactRequirements::for_rules(rules.write_rules.iter().copied());
    let bundle = decl_match_facts_for_retention(
        ws,
        file,
        Some(file_index),
        DeclMatchFactsRequest {
            factory: &rules.factory,
            requirements,
            retention,
            compiler_imports: ctx.file_imports,
            global_headers: ctx.global_headers,
            call_result_type_decls: None,
        },
    );
    for r in &file_index.refs {
        if r.kind != RefKind::Write {
            continue;
        }
        let enclosing_decl = innermost_decl_for_span(decls, r.span);
        let assignment = file_index
            .assignment_values
            .iter()
            .find(|fact| fact.target_span == Some(r.span));
        let constraint_span = assignment.map_or(r.span, |fact| fact.assignment_span);
        let rendered_value = assignment.and_then(|fact| {
            let source = source_text.as_deref()?;
            source.get(fact.value_span.start as usize..fact.value_span.end as usize)
        });
        let argument = CallArg {
            passing_mode: Default::default(),
            span: assignment.map_or(r.span, |fact| fact.value_span),
            name: None,
            place: None,
            source_names: Vec::new(),
            value_text: rendered_value.unwrap_or_default().to_string(),
        };
        let args = [argument];
        let ast_values = [rendered_value.into_iter().map(str::to_string).collect::<Vec<_>>()];
        let Some(decl) = enclosing_decl else {
            continue;
        };
        let Some(facts) = bundle.by_decl_span.get(&decl.span) else {
            continue;
        };
        for prepared in &rules.write_rules {
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
            let mut receiver_types =
                exact_declared_receiver_types_for_match_base(decl, &r.name, ctx.file_imports);
            append_derived_receiver_types_for_match_base(
                &mut receiver_types,
                &facts.derived_type_aliases,
                &r.name,
            );
            if !base_receiver_type_allows(
                prepared,
                Some(decl),
                &r.name,
                &receiver_types,
                &facts.derived_type_aliases,
            ) || external_receiver_type_is_workspace_shadow_at(
                prepared,
                &receiver_types,
                &file_index.defs,
                ctx.file_imports,
                Some(&r.name),
            ) {
                continue;
            }
            if !prepared.call_context_allows(&r.name, &receiver_types, &facts.alias_map, file_packages) {
                continue;
            }
            if prepared_write_binding_origin_is_invalid(
                ws,
                file,
                prepared,
                decl,
                &file_index.defs,
                &r.name,
                r.span,
                &facts.alias_map,
                ctx.file_imports,
            ) {
                continue;
            }
            if out
                .iter()
                .any(|existing| existing.rule_id == prepared.rule.id && existing.span == constraint_span)
            {
                continue;
            }
            if !constraints_pass(ConstraintEval {
                rule_id: &prepared.rule.id,
                callee: &r.name,
                receiver: None,
                args: &args,
                receiver_types: &receiver_types,
                span: constraint_span,
                call_origin: Some(CallFactOrigin::SyntheticWrite),
                constraints: &prepared.rule.constraints.0,
                constraint_regexes: &prepared.constraint_regexes,
                receiver_call_count: None,
                assignment_texts: None,
                ast_arg_values: Some(&ast_values),
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
                    string_compositions: &file_index.string_compositions,
                    factory_import_identity: None,
                }),
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
            let enclosing_fn = Some(decl.name.clone());
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
                    let Some(name) = canonical_lifecycle_binding(name) else {
                        continue;
                    };
                    if transition.is_empty() {
                        continue;
                    }
                    out.push((*span, name, transition.clone()));
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

/// Restore the exact parsed receiver on assignment-source call projections.
///
/// `FlowEvent::Assign` intentionally keeps a compact value-producer name, but
/// `AssignmentValueFact` owns the syntax relationship between that producer
/// and its receiver. Joining by the assignment span preserves typed property
/// getters and other accessor-shaped values without reconstructing a receiver
/// from the rendered callee string.
fn enrich_assignment_call_fact_receivers(
    calls: &mut [CallFact],
    assignment_values: &[bonsai_lang_api::AssignmentValueFact],
) {
    for call in calls {
        if call.origin != CallFactOrigin::AssignmentSourceCall {
            continue;
        }
        let Some(fact) = bonsai_lang_api::assignment_value_fact_for_span(assignment_values, call.span) else {
            continue;
        };
        if fact.direct_call_name.as_deref() != Some(call.callee.as_str())
            || fact.direct_call_receiver_span.is_none()
        {
            continue;
        }
        let Some(receiver) = fact
            .direct_call_receiver
            .as_ref()
            .filter(|receiver| !receiver.is_empty())
        else {
            continue;
        };
        call.receiver = Some(receiver.clone());
        call.call_kind = CallKind::Method;
    }
}

fn enrich_call_fact_receiver_types(calls: &mut [CallFact], aliases: &[TypeAliasBinding]) {
    if aliases.is_empty() {
        return;
    }
    for call in calls {
        // The adapter's receiver field is the canonical structural fact.
        // Some grammars intentionally lower a method call as a bare callee
        // plus an exact receiver (for example Rust fluent filter calls), so
        // deriving the receiver only from the display-form callee silently
        // drops otherwise-proven rulepack return typing.
        let Some(receiver) = call
            .receiver
            .as_deref()
            .or_else(|| call_receiver_text(&call.callee))
        else {
            continue;
        };
        let receiver = normalize_leading_call_punctuation(receiver.trim());
        for alias in aliases {
            let alias_name = normalize_leading_call_punctuation(&alias.name);
            if alias_name == receiver || receiver_root_name(receiver).as_deref() == Some(alias_name) {
                push_unique_string(&mut call.receiver_types, alias.type_name.clone());
            }
        }
    }
}

/// Expand only adapter-emitted receiver types through the file's exact
/// compiler import bindings. The original source spelling is retained so
/// lexical shadow/ambiguity checks can still fail closed, while an imported
/// nested type such as `Provider.Builder` also carries its complete external
/// identity for rule-owned receiver constraints.
fn enrich_call_fact_receiver_import_types(
    calls: &mut [CallFact],
    import_aliases: &std::collections::HashMap<String, AliasTarget>,
) {
    for call in calls {
        append_import_expanded_type_identities(&mut call.receiver_types, import_aliases);
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
                receiver,
                span,
                args,
                receiver_types,
                call_kind,
                ..
            } => {
                out.push(CallFact {
                    callee: name.clone(),
                    receiver: receiver.clone(),
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
                    receiver: None,
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
    if let Some(regex) = regex {
        // A canonical compiler place may include an implicit receiver
        // (`this.client.get`) while a rule intentionally targets the
        // receiver's declared type (`HttpClient.get`). Reconstruct that
        // rule-facing identity exclusively from adapter-emitted type facts
        // plus the compiler-emitted method tail. This is typed matching, not
        // API-name inference: provider vocabulary remains entirely in the
        // rule regex. A call-expression receiver is deliberately excluded:
        // the declared type of `client` does not prove the return type of
        // `client.get()` in `client.get().uri(...)`. Rules for fluent chains
        // match the adapter-emitted chain directly.
        let receiver = callee.rsplit_once('.').map_or("", |(receiver, _)| receiver);
        if receiver.contains(['(', ')']) {
            return false;
        }
        let method = bonsai_common::short_qualified_tail(callee).trim();
        if method.is_empty() {
            return false;
        }
        return receiver_types.iter().any(|receiver_type| {
            let receiver_type = receiver_type.trim();
            if receiver_type.is_empty() {
                return false;
            }
            let typed_callee = format!("{receiver_type}.{method}");
            if regex.is_match(&typed_callee) {
                return true;
            }
            let simple_type = bonsai_common::short_qualified_tail(receiver_type).trim();
            simple_type != receiver_type
                && !simple_type.is_empty()
                && regex.is_match(&format!("{simple_type}.{method}"))
        });
    }
    attribute.is_some_and(|attr| receiver_type_attribute_matches(callee, receiver_types, attr))
}

/// Match an adapter-emitted call against a rulepack-owned callable target.
/// This is shared by the ordinary rule matcher and structured guard proofs so
/// analysis helpers never grow their own API-name comparisons.
pub(crate) fn rule_target_matches_call(callee: &str, receiver_types: &[String], target: &RuleTarget) -> bool {
    if target.annotation.is_some()
        || target.default_call.is_some()
        || target.param_default_calls_absent.is_some()
        || !target.in_class.is_empty()
        || !target.in_class_suffix.is_empty()
        || !target.in_owner_base.is_empty()
        || !target.in_method.is_empty()
        || !target.in_method_prefix.is_empty()
        || !target.param_index_in.is_empty()
        || !target.param_index_not_in.is_empty()
        || !target.param_type_in.is_empty()
        || !target.param_type_exact_in.is_empty()
        || !target.signature_param_types.is_empty()
        || !target.signature_param_annotations.is_empty()
        || !target.param_count_in.is_empty()
        || !target.base_param_index_in.is_empty()
        || !target.decl_kind_in.is_empty()
        || !target.visibility_in.is_empty()
        || !target.call_kind_in.is_empty()
    {
        // This helper has a callee and receiver types, but no declaration or
        // typed call-kind context. Contextual constraints must fail closed
        // instead of being silently ignored.
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
        || (expected.len() == 1
            && actual
                .last()
                .zip(expected.last())
                .is_some_and(|(actual, expected)| actual == expected))
}

fn receiver_type_matches_any(actual: &[String], expected: &[String]) -> bool {
    actual.iter().any(|actual| {
        expected.iter().any(|expected| {
            // A rule-owned receiver type is one semantic identity even when
            // its source ecosystem spells it with qualification
            // (`Net::AMQP::RabbitMQ`, `java.sql.Connection`).  Compare the
            // compiler and rule identities as structural segments; wrapping
            // the complete rule string in a one-element slice makes every
            // qualified type unreachable because the compiler side is
            // already segmented.
            let expected_segments = bonsai_common::qualified_name_segments(expected)
                .into_iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>();
            type_name_matches_attribute_prefix(actual, &expected_segments)
        })
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
    if normalized == method || bonsai_common::short_qualified_tail(normalized) == method {
        return true;
    }
    // Some adapters preserve a multipart callable suffix as one exact
    // source-level selector in the rule target while the language-neutral
    // qualified-name view exposes each identifier-shaped component. Compare
    // those already-compiled components as an exact suffix; no punctuation
    // spelling or API vocabulary is interpreted here.
    let actual = bonsai_common::qualified_name_segments(normalized);
    let expected = bonsai_common::qualified_name_segments(method);
    !expected.is_empty() && actual.ends_with(&expected)
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
        // A rule target is one exact call, never an arbitrary component of a
        // fluent-chain rendering. Adapters lower nested calls independently,
        // so matching an interior window here would bind the rule's argument
        // constraints to the outer call's arguments (`Command::new(literal)
        // .args(tainted)` would falsely treat the tainted argv as `new` arg
        // zero). Keep only exact/suffix identities and let the compiler fact
        // for the nested call match on its own.
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
            ConstraintKind::RequiresPriorReceiverCall {
                requires_prior_receiver_call,
            } => Some(compile_constraint_regex(
                rule_id,
                "constraints.requires_prior_receiver_call.static_string_args_regex",
                &requires_prior_receiver_call.static_string_args_regex,
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
            ConstraintKind::ArgStringCompositionStartsWith {
                arg_string_composition_starts_with: spec,
            }
            | ConstraintKind::ArgStringCompositionNotStartsWith {
                arg_string_composition_not_starts_with: spec,
            } => match spec.literal_regex.as_deref() {
                Some(pattern) => Some(compile_constraint_regex(
                    rule_id,
                    "constraints.string_composition.literal_regex",
                    pattern,
                )?),
                None => None,
            },
            ConstraintKind::ReceiverTypeIn { .. }
            | ConstraintKind::ReceiverTypeNotIn { .. }
            | ConstraintKind::RequiresPriorReceiverWrite { .. }
            | ConstraintKind::SecondArgEquals { .. }
            | ConstraintKind::ArgEquals { .. }
            | ConstraintKind::KeywordArgEquals { .. }
            | ConstraintKind::ArgTainted { .. }
            | ConstraintKind::ReceiverTainted { .. }
            | ConstraintKind::AnyArgTainted { .. }
            | ConstraintKind::ReceiverOriginCallbackParamReachesCall { .. }
            | ConstraintKind::ReceiverFactoryArgumentFieldsEqual { .. }
            | ConstraintKind::ReceiverFactoryArgumentsEqual { .. }
            | ConstraintKind::FormatArgIndex { .. }
            | ConstraintKind::Namespace { .. }
            | ConstraintKind::TopLevel { .. }
            | ConstraintKind::ArgCount { .. }
            | ConstraintKind::MinArgs { .. }
            | ConstraintKind::MaxArgs { .. }
            | ConstraintKind::ArgValueNotAggregate { .. }
            | ConstraintKind::ArgValueKind { .. }
            | ConstraintKind::ArgIsInlineCallback { .. }
            | ConstraintKind::ArgInlineCallbackReturnsStatic { .. }
            | ConstraintKind::ArgSequenceItemsEqual { .. }
            | ConstraintKind::ArgAggregateFieldsEqual { .. }
            | ConstraintKind::SameReceiverCallCountAtLeast { .. }
            | ConstraintKind::ArgLt { .. }
            | ConstraintKind::ArgLe { .. }
            | ConstraintKind::ArgGt { .. }
            | ConstraintKind::ArgGe { .. }
            | ConstraintKind::RequiresRuntimeType { .. }
            | ConstraintKind::EnclosingDecoratorIn { .. }
            | ConstraintKind::EnclosingDecoratorNotIn { .. }
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
    string_compositions: &'a [bonsai_lang_api::StringCompositionFact],
    factory_import_identity: Option<FactoryImportIdentityContext<'a>>,
}

#[derive(Clone, Copy)]
struct FactoryImportIdentityContext<'a> {
    required_imports: &'a [String],
    alias_map: &'a std::collections::HashMap<String, AliasTarget>,
    compiler_imports: Option<&'a bonsai_lang_api::ImportIndex>,
    workspace: Option<(&'a Workspace, &'a GlobalIndex)>,
}

fn argument_string_composition_starts_with(
    structural: StructuralConstraintContext<'_>,
    call_span: Span,
    argument_index: usize,
    required: &crate::rule::ArgStringCompositionPrefixSpec,
    literal_regex: Option<&Regex>,
) -> bool {
    if required.literal_regex.is_some() && literal_regex.is_none() {
        return false;
    }
    let Some(argument) =
        bonsai_lang_api::call_argument_value_fact(structural.call_argument_values, call_span, argument_index)
    else {
        return false;
    };
    structural.string_compositions.iter().any(|composition| {
        composition.value_span == argument.argument_span
            && composition.parts.len() > 1
            && matches!(
                composition.parts.first(),
                Some(bonsai_lang_api::StringCompositionPart::Literal { value })
                    if string_composition_literal_matches(value, required)
                        && literal_regex.is_none_or(|regex| regex.is_match(value))
            )
            && composition
                .parts
                .iter()
                .skip(1)
                .any(|part| !matches!(part, bonsai_lang_api::StringCompositionPart::Literal { .. }))
    })
}

fn string_composition_literal_matches(
    value: &str,
    required: &crate::rule::ArgStringCompositionPrefixSpec,
) -> bool {
    let candidate = if required.allow_prefix {
        let Some(prefix) = value.get(..required.value.len()) else {
            return false;
        };
        prefix
    } else {
        value
    };
    if required.ascii_case_insensitive {
        candidate.eq_ignore_ascii_case(&required.value)
    } else {
        candidate == required.value
    }
}

/// Prove an aggregate through exact local copies in the consumer's basic
/// block. Calls/control transfers stop the proof: an unknown clobber or a
/// branch cannot lend a stale initializer to this argument. This is a shape
/// predicate only; it does not remove any IDG value or taint edge.
fn argument_has_straight_line_aggregate_value(
    structural: StructuralConstraintContext<'_>,
    call_span: Span,
    argument: &bonsai_lang_api::CallArgumentValueFact,
) -> bool {
    let aggregate = |flow: &bonsai_lang_api::ExpressionFlow| {
        !flow.aggregate_fields.is_empty() || !flow.tuple_items.is_empty() || !flow.spreads.is_empty()
    };
    if aggregate(&argument.value_flow) || argument.exact_static_sequence_values.is_some() {
        return true;
    }
    let exact_place = |flow: &bonsai_lang_api::ExpressionFlow| {
        flow.projection.is_none() && flow.call_sites.is_empty() && flow.source_names.len() <= 1
    };
    if !exact_place(&argument.value_flow) {
        return false;
    }
    let Some(mut place) = argument.value_flow.place.as_deref() else {
        return false;
    };
    let events = &structural.current_decl.flow_events;
    let Some(consumer) = events
        .iter()
        .position(|event| matches!(event, FlowEvent::Call { span, .. } if *span == call_span))
    else {
        return false;
    };
    for event in events[..consumer].iter().rev() {
        let (span, target) = match event {
            FlowEvent::Assign { span, target, .. } | FlowEvent::AggregateAssign { span, target, .. } => {
                (*span, target)
            }
            _ => return false,
        };
        if target != place {
            continue;
        }
        let Some(value) = bonsai_lang_api::assignment_value_fact_for_span(structural.assignment_values, span)
        else {
            return false;
        };
        if aggregate(&value.value_flow) {
            return true;
        }
        if !exact_place(&value.value_flow) {
            return false;
        }
        let Some(source) = value.value_flow.place.as_deref() else {
            return false;
        };
        place = source;
    }
    false
}

#[derive(Copy, Clone)]
struct GuaranteedPriorCall<'a> {
    span: Span,
    name: &'a str,
    receiver: Option<&'a str>,
    receiver_types: &'a [String],
    arg_count: usize,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum ReachingPriorWrite {
    None,
    Known(Span),
    Ambiguous,
}

fn merge_reaching_prior_writes(left: ReachingPriorWrite, right: ReachingPriorWrite) -> ReachingPriorWrite {
    if left == right {
        left
    } else {
        ReachingPriorWrite::Ambiguous
    }
}

fn flow_event_contains_span(event: &FlowEvent, target: Span) -> bool {
    let event_span = match event {
        FlowEvent::Call { span, .. }
        | FlowEvent::Branch { span, .. }
        | FlowEvent::Loop { span, .. }
        | FlowEvent::Assign { span, .. }
        | FlowEvent::AggregateAssign { span, .. }
        | FlowEvent::Return { span, .. }
        | FlowEvent::Throw { span, .. }
        | FlowEvent::Try { span, .. }
        | FlowEvent::Break { span, .. }
        | FlowEvent::Continue { span, .. }
        | FlowEvent::Yield { span, .. }
        | FlowEvent::Await { span, .. }
        | FlowEvent::Defer { span, .. }
        | FlowEvent::Using { span, .. }
        | FlowEvent::Lifecycle { span, .. } => *span,
    };
    event_span == target
        || spans_overlap(event_span, target)
        || (event_span.start <= target.start && target.end <= event_span.end)
}

fn events_contain_span(events: &[FlowEvent], target: Span) -> bool {
    events.iter().any(|event| flow_event_contains_span(event, target))
}

fn receiver_write_matches(target: &str, receiver: &str, member: &RuleTarget) -> bool {
    call_receiver_text(target).is_some_and(|candidate| candidate == receiver)
        && rule_target_matches_call(target, &[], member)
}

/// Compute the exact reaching definition for one rule-declared member on a
/// compiler receiver.  Completed branches merge by equality; loops include
/// the zero-iteration predecessor; exception regions include the entry path.
/// Any disagreement becomes `Ambiguous`, so state constraints fail closed.
fn reaching_prior_receiver_write(
    events: &[FlowEvent],
    target: Span,
    receiver: &str,
    member: &RuleTarget,
) -> ReachingPriorWrite {
    fn walk(
        events: &[FlowEvent],
        target: Span,
        receiver: &str,
        member: &RuleTarget,
        state: &mut ReachingPriorWrite,
    ) -> bool {
        for event in events {
            match event {
                FlowEvent::Assign {
                    span,
                    target: write_target,
                    ..
                }
                | FlowEvent::AggregateAssign {
                    span,
                    target: write_target,
                    ..
                } => {
                    if flow_event_contains_span(event, target) {
                        return true;
                    }
                    if span.end <= target.start && receiver_write_matches(write_target, receiver, member) {
                        *state = ReachingPriorWrite::Known(*span);
                    }
                }
                FlowEvent::Branch {
                    then_events,
                    else_events,
                    ..
                } => {
                    if events_contain_span(then_events, target) {
                        return walk(then_events, target, receiver, member, state);
                    }
                    if events_contain_span(else_events, target) {
                        return walk(else_events, target, receiver, member, state);
                    }
                    let before = *state;
                    let mut then_state = before;
                    let _ = walk(then_events, target, receiver, member, &mut then_state);
                    let mut else_state = before;
                    let _ = walk(else_events, target, receiver, member, &mut else_state);
                    *state = merge_reaching_prior_writes(then_state, else_state);
                }
                FlowEvent::Loop { body, .. } => {
                    if events_contain_span(body, target) {
                        return walk(body, target, receiver, member, state);
                    }
                    let before = *state;
                    let mut body_state = before;
                    let _ = walk(body, target, receiver, member, &mut body_state);
                    *state = merge_reaching_prior_writes(before, body_state);
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
                        if events_contain_span(region, target) {
                            return walk(region, target, receiver, member, state);
                        }
                    }
                    let before = *state;
                    let mut body_state = before;
                    let _ = walk(body, target, receiver, member, &mut body_state);
                    let mut catch_state = before;
                    let _ = walk(catch_events, target, receiver, member, &mut catch_state);
                    *state = merge_reaching_prior_writes(
                        before,
                        merge_reaching_prior_writes(body_state, catch_state),
                    );
                    let _ = walk(finally_events, target, receiver, member, state);
                }
                FlowEvent::Using { body, .. } => {
                    if events_contain_span(body, target) {
                        return walk(body, target, receiver, member, state);
                    }
                    let _ = walk(body, target, receiver, member, state);
                }
                // Deferred bodies execute after the current expression and
                // cannot establish its reaching state.
                FlowEvent::Defer { .. } => {}
                _ => {
                    if flow_event_contains_span(event, target) {
                        return true;
                    }
                }
            }
        }
        false
    }

    let mut state = ReachingPriorWrite::None;
    let _ = walk(events, target, receiver, member, &mut state);
    state
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
    /// Exact receiver expression emitted by the language adapter. Synthetic
    /// write/ref paths leave this absent and retain the legacy qualified
    /// callee fallback below.
    receiver: Option<&'a str>,
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
/// | `ArgIsInlineCallback`        | parsed argument is an inline callback              |
/// | `ArgInlineCallbackReturnsStatic` | inline callback has one exact scalar return    |
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
                let Some(receiver) = ctx.receiver.or_else(|| call_receiver_text(ctx.callee)) else {
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
                let Some(receiver) = ctx.receiver.or_else(|| call_receiver_text(ctx.callee)) else {
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
                let Some(receiver) = ctx.receiver.or_else(|| call_receiver_text(ctx.callee)) else {
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
            ConstraintKind::RequiresPriorReceiverCall {
                requires_prior_receiver_call,
            } => {
                let Some(receiver) = ctx.receiver.or_else(|| call_receiver_text(ctx.callee)) else {
                    return false;
                };
                let Some(Some(re)) = ctx.constraint_regexes.get(constraint_index) else {
                    return false;
                };
                let Some(structural) = ctx.structural_context else {
                    return false;
                };
                let owner = structural
                    .file_decls
                    .iter()
                    .filter(|decl| decl.span.start <= ctx.span.start && ctx.span.end <= decl.span.end)
                    .min_by_key(|decl| decl.span.end.saturating_sub(decl.span.start))
                    .unwrap_or(structural.current_decl);
                let mut prior_calls = Vec::new();
                collect_guaranteed_prior_calls(&owner.flow_events, ctx.span, &mut prior_calls);
                if !prior_calls.iter().any(|call| {
                    call.receiver == Some(receiver)
                        && rule_target_matches_call(
                            call.name,
                            call.receiver_types,
                            &requires_prior_receiver_call.call,
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
            ConstraintKind::RequiresPriorReceiverWrite {
                requires_prior_receiver_write,
            } => {
                let Some(receiver) = ctx.receiver.or_else(|| call_receiver_text(ctx.callee)) else {
                    return false;
                };
                let Some(structural) = ctx.structural_context else {
                    return false;
                };
                if requires_prior_receiver_write.accepted_values.is_empty()
                    && requires_prior_receiver_write.accepted_calls.is_empty()
                {
                    return false;
                }
                let owner = structural
                    .file_decls
                    .iter()
                    .filter(|decl| decl.span.start <= ctx.span.start && ctx.span.end <= decl.span.end)
                    .min_by_key(|decl| decl.span.end.saturating_sub(decl.span.start))
                    .unwrap_or(structural.current_decl);
                let reaching = reaching_prior_receiver_write(
                    &owner.flow_events,
                    ctx.span,
                    receiver,
                    &requires_prior_receiver_write.target,
                );
                let ReachingPriorWrite::Known(write_span) = reaching else {
                    return false;
                };
                let Some(value_fact) =
                    bonsai_lang_api::assignment_value_fact_for_span(structural.assignment_values, write_span)
                else {
                    return false;
                };
                let scalar_matches = value_fact
                    .static_value
                    .as_ref()
                    .is_some_and(|value| requires_prior_receiver_write.accepted_values.contains(value));
                let call_matches = requires_prior_receiver_write
                    .accepted_calls
                    .iter()
                    .any(|accepted| {
                        value_fact.direct_call_name.as_deref().is_some_and(|callee| {
                            structural.factory_import_identity.map_or_else(
                                || rule_target_matches_call(callee, &[], &accepted.call),
                                |identity| {
                                    let target_matches = rule_target_matches_call_with_aliases(
                                        callee,
                                        &[],
                                        &accepted.call,
                                        identity.alias_map,
                                    );
                                    if !target_matches {
                                        return false;
                                    }
                                    let Some(origin) = accepted.call.binding_origin else {
                                        return factory_import_identity_allows(callee, identity);
                                    };
                                    let synthetic = CallFact {
                                        callee: callee.to_string(),
                                        receiver: None,
                                        span: value_fact.value_span,
                                        args: Vec::new(),
                                        receiver_types: Vec::new(),
                                        call_kind: CallKind::Function,
                                        origin: CallFactOrigin::SyntheticWrite,
                                    };
                                    let workspace_context =
                                        identity
                                            .workspace
                                            .map(|(ws, global)| WorkspaceCallIdentityContext {
                                                ws,
                                                global,
                                                caller: structural.current_decl,
                                            });
                                    call_binding_origin_is_valid(
                                        origin,
                                        true,
                                        structural.current_decl,
                                        Some(structural.file_decls),
                                        workspace_context.as_ref(),
                                        &synthetic,
                                        identity.alias_map,
                                        identity.required_imports,
                                        identity.compiler_imports,
                                    )
                                },
                            )
                        }) && value_fact
                            .exact_static_call_args
                            .as_ref()
                            .is_some_and(|arguments| {
                                accepted.items.iter().all(|required| {
                                    arguments
                                        .get(required.index)
                                        .is_some_and(|actual| required.accepted_values.contains(actual))
                                })
                            })
                    });
                if !scalar_matches && !call_matches {
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
                if !format_arg_is_dynamic(ctx, idx, arg) {
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
                let found = ctx.args.iter().any(|arg| {
                    arg.name.as_deref() == Some(keyword_arg_equals.name.as_str())
                        && arg.value_text.trim() == keyword_arg_equals.value
                });
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
            ConstraintKind::ReceiverFactoryArgumentFieldsEqual {
                receiver_factory_argument_fields_equal,
            } => {
                let Some(structural) = ctx.structural_context else {
                    return false;
                };
                if receiver_factory_argument_fields_proof(
                    ctx.callee,
                    ctx.span,
                    structural,
                    receiver_factory_argument_fields_equal,
                )
                .is_none()
                {
                    return false;
                }
            }
            ConstraintKind::ReceiverFactoryArgumentsEqual {
                receiver_factory_arguments_equal,
            } => {
                let Some(structural) = ctx.structural_context else {
                    return false;
                };
                if !receiver_factory_arguments_equal_passes(ctx, structural, receiver_factory_arguments_equal)
                {
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
                .is_some_and(|fact| argument_has_straight_line_aggregate_value(structural, ctx.span, fact))
                {
                    return false;
                }
            }
            ConstraintKind::ArgValueKind { arg_value_kind } => {
                let Some(structural) = ctx.structural_context else {
                    return false;
                };
                if bonsai_lang_api::call_argument_value_fact(
                    structural.call_argument_values,
                    ctx.span,
                    arg_value_kind.index as usize,
                )
                .is_none_or(|fact| fact.value_kind != Some(arg_value_kind.kind))
                {
                    return false;
                }
            }
            ConstraintKind::ArgStringCompositionStartsWith {
                arg_string_composition_starts_with,
            } => {
                let Some(structural) = ctx.structural_context else {
                    return false;
                };
                if !argument_string_composition_starts_with(
                    structural,
                    ctx.span,
                    arg_string_composition_starts_with.index as usize,
                    arg_string_composition_starts_with,
                    ctx.constraint_regexes
                        .get(constraint_index)
                        .and_then(Option::as_ref),
                ) {
                    return false;
                }
            }
            ConstraintKind::ArgStringCompositionNotStartsWith {
                arg_string_composition_not_starts_with,
            } => {
                let Some(structural) = ctx.structural_context else {
                    continue;
                };
                if argument_string_composition_starts_with(
                    structural,
                    ctx.span,
                    arg_string_composition_not_starts_with.index as usize,
                    arg_string_composition_not_starts_with,
                    ctx.constraint_regexes
                        .get(constraint_index)
                        .and_then(Option::as_ref),
                ) {
                    return false;
                }
            }
            ConstraintKind::ArgIsInlineCallback {
                arg_is_inline_callback,
            } => {
                let Some(structural) = ctx.structural_context else {
                    return false;
                };
                if bonsai_lang_api::call_argument_value_fact(
                    structural.call_argument_values,
                    ctx.span,
                    *arg_is_inline_callback as usize,
                )
                .is_none_or(|fact| fact.inline_callback_span.is_none())
                {
                    return false;
                }
            }
            ConstraintKind::ArgInlineCallbackReturnsStatic {
                arg_inline_callback_returns_static,
            } => {
                let Some(structural) = ctx.structural_context else {
                    return false;
                };
                let call_argument_matches = bonsai_lang_api::call_argument_value_fact(
                    structural.call_argument_values,
                    ctx.span,
                    arg_inline_callback_returns_static.index as usize,
                )
                .is_some_and(|fact| {
                    fact.inline_callback_static_return.as_ref()
                        == Some(&arg_inline_callback_returns_static.value)
                });
                let write_rhs_matches = ctx.call_origin == Some(CallFactOrigin::SyntheticWrite)
                    && arg_inline_callback_returns_static.index == 0
                    && bonsai_lang_api::assignment_value_fact_for_span(
                        structural.assignment_values,
                        ctx.span,
                    )
                    .is_some_and(|fact| {
                        fact.inline_callback_static_return.as_ref()
                            == Some(&arg_inline_callback_returns_static.value)
                    });
                if !call_argument_matches && !write_rhs_matches {
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
            ConstraintKind::ArgAggregateFieldsEqual {
                arg_aggregate_fields_equal,
            } => {
                let Some(structural) = ctx.structural_context else {
                    return false;
                };
                let Some(argument) = bonsai_lang_api::call_argument_value_fact(
                    structural.call_argument_values,
                    ctx.span,
                    arg_aggregate_fields_equal.argument_index,
                ) else {
                    return false;
                };
                if !argument.value_flow.spreads.is_empty()
                    || argument.exact_static_aggregate_fields.is_empty()
                    || arg_aggregate_fields_equal.required_fields.is_empty()
                    || !arg_aggregate_fields_equal.required_fields.iter().all(|required| {
                        !required.path.is_empty()
                            && argument
                                .exact_static_aggregate_fields
                                .iter()
                                .any(|actual| actual.path == required.path && actual.value == required.value)
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
                let Some(subject) = call_arg_single_value_identity(arg) else {
                    return false;
                };
                let Some(narrowings) = ctx.runtime_types else {
                    return false;
                };
                let observed = runtime_type_at(narrowings, &subject, ctx.span.start);
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
            ConstraintKind::EnclosingDecoratorNotIn {
                enclosing_decorator_not_in,
            } => {
                if enclosing_decorator_not_in.is_empty() {
                    return false;
                }
                let Some(decorators) = ctx.enclosing_decorators else {
                    return false;
                };
                if decorators.iter().any(|attached| {
                    enclosing_decorator_not_in
                        .iter()
                        .any(|blocked| blocked == attached)
                }) {
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
                let Some(src_n) = call_arg_single_value_identity(src_arg) else {
                    return false;
                };
                let Some(sink_n) = call_arg_single_value_identity(sink_arg) else {
                    return false;
                };
                if src_n != sink_n {
                    let Some(chains) = ctx.alias_chains else {
                        return false;
                    };
                    let src_root = chains.get(&src_n).map(String::as_str).unwrap_or(&src_n);
                    let sink_root = chains.get(&sink_n).map(String::as_str).unwrap_or(&sink_n);
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
                let binding: Option<String> = match (&requires_state.name, requires_state.index) {
                    (Some(name), _) => Some(name.clone()),
                    (None, Some(index)) => ctx
                        .args
                        .get(index as usize)
                        .and_then(call_arg_single_value_identity),
                    (None, None) => None,
                };
                let Some(binding) = binding.as_deref().and_then(canonical_lifecycle_binding) else {
                    return false;
                };
                let observed = lifecycle_state_at(transitions, &binding, ctx.span.start);
                if observed.as_deref() != Some(requires_state.expected.as_str()) {
                    return false;
                }
            }
        }
    }
    true
}

fn call_arg_single_value_identity(arg: &CallArg) -> Option<String> {
    if let Some(place) = arg
        .place
        .as_deref()
        .map(str::trim)
        .filter(|place| !place.is_empty())
    {
        return canonical_lifecycle_binding(place);
    }
    let mut sources = arg
        .source_names
        .iter()
        .filter_map(|source| canonical_lifecycle_binding(source))
        .collect::<Vec<_>>();
    sources.sort();
    sources.dedup();
    let [only] = sources.as_slice() else {
        return None;
    };
    Some(only.clone())
}

struct ReceiverFactoryArgumentFieldsProof {
    assignment_span: Span,
    factory_name: String,
}

fn declaration_is_lexically_visible_from(owner: &Decl, current: &Decl, file_decls: &[Decl]) -> bool {
    let is_compiler_module = owner.name == bonsai_lang_api::MODULE_DECL_NAME
        && owner.name_span == owner.span
        && owner.body_span == Some(owner.span);
    if owner.symbol == current.symbol || is_compiler_module {
        return true;
    }
    let mut parent = current.parent;
    while let Some(symbol) = parent {
        let Some(ancestor) = file_decls.iter().find(|decl| decl.symbol == symbol) else {
            return false;
        };
        if ancestor.symbol == owner.symbol {
            return true;
        }
        parent = ancestor.parent;
    }
    false
}

fn assignment_is_lexically_visible_from(
    assignment: &bonsai_lang_api::AssignmentValueFact,
    current: &Decl,
    file_decls: &[Decl],
) -> bool {
    innermost_decl_for_span(file_decls, assignment.assignment_span)
        .is_some_and(|owner| declaration_is_lexically_visible_from(owner, current, file_decls))
}

fn factory_import_identity_allows(actual: &str, identity: FactoryImportIdentityContext<'_>) -> bool {
    if identity.required_imports.is_empty() {
        return true;
    }
    let Some(head) = bonsai_common::qualified_name_segments(actual)
        .first()
        .map(|head| normalize_leading_call_punctuation(head).to_string())
    else {
        return false;
    };
    let mut key = head;
    let mut visited = AHashSet::new();
    while visited.insert(key.clone()) {
        match identity.alias_map.get(&key) {
            Some(AliasTarget::Member { module, .. } | AliasTarget::Namespace { module }) => {
                return identity
                    .required_imports
                    .iter()
                    .any(|wanted| import_module_matches(module, wanted));
            }
            Some(AliasTarget::Type { type_name }) => {
                let segments = bonsai_common::qualified_name_segments(type_name);
                let Some(next) = segments.first() else {
                    return false;
                };
                key = normalize_leading_call_punctuation(next).to_string();
            }
            None => return false,
        }
    }
    false
}

fn receiver_factory_arguments_equal_passes(
    ctx: &ConstraintEval<'_, '_>,
    structural: StructuralConstraintContext<'_>,
    spec: &ReceiverFactoryArgumentsSpec,
) -> bool {
    let Some(receiver) = ctx.receiver.or_else(|| call_receiver_text(ctx.callee)) else {
        return false;
    };
    if spec.items.is_empty() {
        return false;
    }
    let Some(assignment) = structural
        .assignment_values
        .iter()
        .filter(|assignment| {
            assignment.assignment_span.end <= ctx.span.start
                && assignment.target.as_deref() == Some(receiver)
                && assignment_is_lexically_visible_from(
                    assignment,
                    structural.current_decl,
                    structural.file_decls,
                )
        })
        .max_by_key(|assignment| (assignment.assignment_span.end, assignment.assignment_span.start))
    else {
        return false;
    };
    let factory_matches = assignment.direct_call_name.as_deref().is_some_and(|callee| {
        structural.factory_import_identity.map_or_else(
            || rule_target_matches_call(callee, &[], &spec.factory),
            |identity| {
                rule_target_matches_call_with_aliases(callee, &[], &spec.factory, identity.alias_map)
                    && factory_import_identity_allows(callee, identity)
            },
        )
    });
    if !factory_matches {
        return false;
    }
    let Some(arguments) = assignment.exact_static_call_args.as_ref() else {
        return false;
    };
    spec.items.iter().all(|required| {
        arguments
            .get(required.index)
            .is_some_and(|actual| required.accepted_values.contains(actual))
    })
}

fn receiver_factory_argument_fields_proof(
    callee: &str,
    call_span: Span,
    structural: StructuralConstraintContext<'_>,
    spec: &crate::rule::ReceiverFactoryArgumentFieldsSpec,
) -> Option<ReceiverFactoryArgumentFieldsProof> {
    let receiver = call_receiver_text(callee)?;
    if spec.required_fields.is_empty()
        || spec
            .required_fields
            .iter()
            .any(|required| required.path.is_empty())
    {
        return None;
    }
    let assignment_candidates: Vec<_> = structural
        .assignment_values
        .iter()
        .filter(|assignment| {
            assignment.target_is_immutable
                && assignment.assignment_span.start < call_span.start
                && assignment_is_lexically_visible_from(
                    assignment,
                    structural.current_decl,
                    structural.file_decls,
                )
                && assignment.target.as_deref() == Some(receiver)
                && assignment.direct_call_name.as_deref().is_some_and(|factory| {
                    structural.factory_import_identity.map_or_else(
                        || rule_target_matches_call(factory, &[], &spec.factory),
                        |identity| {
                            rule_target_matches_call_with_aliases(
                                factory,
                                &[],
                                &spec.factory,
                                identity.alias_map,
                            ) && factory_import_identity_allows(factory, identity)
                        },
                    )
                })
        })
        .collect();
    let assignment = assignment_candidates
        .into_iter()
        .max_by_key(|assignment| (assignment.assignment_span.start, assignment.assignment_span.end))?;
    let receiver_projection_prefix = format!("{receiver}.");
    if structural.assignment_values.iter().any(|later| {
        assignment.assignment_span.end <= later.assignment_span.start
            && later.assignment_span.start < call_span.start
            && later.assignment_span != assignment.assignment_span
            && assignment_is_lexically_visible_from(later, structural.current_decl, structural.file_decls)
            && later
                .target
                .as_deref()
                .is_some_and(|target| target == receiver || target.starts_with(&receiver_projection_prefix))
    }) {
        return None;
    }
    let matching_arguments: Vec<_> = structural
        .call_argument_values
        .iter()
        .filter(|argument| {
            argument.argument_index == spec.configuration_argument_index
                && matcher_span_contains(assignment.value_span, argument.call_span)
        })
        .filter(|argument| argument.value_flow.spreads.is_empty())
        .filter(|argument| {
            spec.required_fields.iter().all(|required| {
                argument
                    .exact_static_aggregate_fields
                    .iter()
                    .any(|actual| actual.path == required.path && actual.value == required.value)
            })
        })
        .collect();
    let [argument] = matching_arguments.as_slice() else {
        return None;
    };
    if argument.exact_static_aggregate_fields.is_empty() {
        return None;
    }
    Some(ReceiverFactoryArgumentFieldsProof {
        assignment_span: assignment.assignment_span,
        factory_name: assignment.direct_call_name.clone()?,
    })
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

/// Reattribute a tainted configured-receiver call to the immutable factory
/// configuration that made the call dangerous. Matching and IDG closure stay
/// anchored at the real tainted call argument; only the reported sink site is
/// the compiler-proven configuration boundary.
pub(crate) fn configured_receiver_factory_attribution_match(
    ws: &Workspace,
    global: &GlobalIndex,
    sink: &RuleMatch,
    rule: &Rule,
) -> Option<RuleMatch> {
    if rule.match_spec.kind != MatchKind::Call {
        return None;
    }
    let spec = rule.constraints.0.iter().find_map(|constraint| {
        let ConstraintKind::ReceiverFactoryArgumentFieldsEqual {
            receiver_factory_argument_fields_equal,
        } = constraint
        else {
            return None;
        };
        Some(receiver_factory_argument_fields_equal.as_ref())
    })?;
    let file_index = ws.db().decl_index_remapped_to_headers(global, sink.span.file)?;
    let current_decl = file_index
        .defs
        .iter()
        .filter(|decl| decl.span.start <= sink.span.start && sink.span.end <= decl.span.end)
        .min_by_key(|decl| decl.span.end.saturating_sub(decl.span.start))?;
    let alias_map = file_alias_map_with_retention(ws, sink.span.file, FactRetention::Transient);
    let compiler_imports = transient_import_index(ws, sink.span.file);
    let proof = receiver_factory_argument_fields_proof(
        &sink.match_text,
        sink.span,
        StructuralConstraintContext {
            current_decl,
            file_decls: &file_index.defs,
            assignment_values: &file_index.assignment_values,
            call_argument_values: &file_index.call_argument_values,
            string_compositions: &file_index.string_compositions,
            factory_import_identity: Some(FactoryImportIdentityContext {
                required_imports: &rule.imports,
                alias_map: &alias_map,
                compiler_imports: compiler_imports.as_ref(),
                workspace: Some((ws, global)),
            }),
        },
        spec,
    )?;
    let (file, line, column) = resolve_span(ws, proof.assignment_span.file, proof.assignment_span);
    let enclosing_fn = file_index
        .defs
        .iter()
        .filter(|decl| matcher_span_contains(decl.body_span.unwrap_or(decl.span), proof.assignment_span))
        .min_by_key(|decl| decl.span.len())
        .map(|decl| decl.name.clone());
    let mut attributed = sink.clone();
    attributed.file = file;
    attributed.line = line;
    attributed.column = column;
    attributed.span = proof.assignment_span;
    attributed.match_text = proof.factory_name;
    attributed.enclosing_fn = enclosing_fn;
    Some(attributed)
}

fn matcher_span_contains(outer: Span, inner: Span) -> bool {
    outer.file == inner.file && outer.start <= inner.start && inner.end <= outer.end
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
            string_compositions: &file_index.string_compositions,
            factory_import_identity: None,
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

/// Resolve an `arg_tainted` spec to a concrete arg index. Positional
/// specs are bounds-checked; keyword specs consume only the exact named-
/// argument identity emitted by the active language adapter.
fn resolve_arg_tainted_index(args: &[CallArg], spec: &ArgTaintedSpec) -> Option<usize> {
    if let Some(index) = spec.index {
        let index = index as usize;
        return (index < args.len()).then_some(index);
    }
    let keyword = spec.kw.as_deref()?;
    args.iter()
        .enumerate()
        .find_map(|(idx, arg)| (arg.name.as_deref() == Some(keyword)).then_some(idx))
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
/// Literal identity comes from the active adapter's AST classifier.
fn format_arg_is_dynamic(ctx: &ConstraintEval<'_, '_>, index: usize, arg: &CallArg) -> bool {
    if arg.place.is_some() || !arg.source_names.is_empty() {
        return true;
    }
    let fact = ctx.structural_context.and_then(|structural| {
        bonsai_lang_api::call_argument_value_fact(structural.call_argument_values, ctx.span, index)
    });
    match fact.and_then(|fact| fact.value_kind) {
        Some(bonsai_lang_api::AssignValueKind::Literal) => false,
        Some(
            bonsai_lang_api::AssignValueKind::CallResult
            | bonsai_lang_api::AssignValueKind::PropertyRead
            | bonsai_lang_api::AssignValueKind::Compound
            | bonsai_lang_api::AssignValueKind::WholeValueSelection
            | bonsai_lang_api::AssignValueKind::Destructure
            | bonsai_lang_api::AssignValueKind::YieldResult
            | bonsai_lang_api::AssignValueKind::CallableReference
            | bonsai_lang_api::AssignValueKind::AddressOfAggregate
            | bonsai_lang_api::AssignValueKind::Unknown,
        )
        | None => true,
    }
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
                    || args.iter().any(|arg| {
                        arg.place.as_deref() == Some(token)
                            || arg.source_names.iter().any(|name| name == token)
                    })
                {
                    return Some(*span);
                }
            }
            FlowEvent::Assign {
                span,
                source_name,
                source_names,
                ..
            } => {
                if source_name.as_deref() == Some(token) || source_names.iter().any(|name| name == token) {
                    return Some(*span);
                }
            }
            FlowEvent::Return {
                span,
                value_name,
                value_flow,
                ..
            } => {
                if value_name.as_deref() == Some(token) || expression_flow_contains_name(value_flow, token) {
                    return Some(*span);
                }
            }
            FlowEvent::Throw { span, value_name, .. } => {
                if value_name.as_deref() == Some(token) {
                    return Some(*span);
                }
            }
            FlowEvent::Yield { span, value_flow, .. } => {
                if expression_flow_contains_name(value_flow, token) {
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

fn expression_flow_contains_name(flow: &bonsai_lang_api::ExpressionFlow, token: &str) -> bool {
    flow.place.as_deref() == Some(token)
        || flow.source_names.iter().any(|name| name == token)
        || flow
            .aggregate_fields
            .iter()
            .any(|field| expression_flow_contains_name(&field.value, token))
        || flow
            .tuple_items
            .iter()
            .any(|item| expression_flow_contains_name(item, token))
        || flow
            .spreads
            .iter()
            .any(|spread| expression_flow_contains_name(spread, token))
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
