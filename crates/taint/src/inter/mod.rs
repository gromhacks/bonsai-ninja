//! Interprocedural taint via the resolver.
//!
//! The intraprocedural pass runs one function at a time with a fixed
//! seed. The interprocedural pass wires those per-function analyses
//! together across the resolved call graph: when a function calls
//! `foo(tainted_x, clean_y)`, this pass propagates taint into
//! `foo`'s parameter scope (seeding `foo`'s first param) and re-runs
//! the intraprocedural pass on `foo` with that new seed. The
//! resolver layer — [`bonsai_resolve`] + per-file alias maps + the
//! global decl index — decides *which* callees a name resolves to,
//! so we follow the same edges the engine's `ResolvedCallGraph`
//! would produce (never a workspace-wide BFS / DFS over strings).
//!
//! ## Guarantees
//!
//! - **Cross-module:** alias rewriting via
//!   [`bonsai_resolve::alias_map_for_file`] on every call site, so
//!   `from x import y as z; z(tainted)` taints `y`'s matching
//!   parameter.
//! - **Semantic edges only:** a call propagates only when resolution
//!   identifies a concrete callee or a semantically narrowed virtual
//!   set. Ambiguous workspace-wide matches are treated as no-flow
//!   instead of being fanned out.
//! - **Recursion-safe:** `(func, taint-set)` pairs are memoized, so
//!   cycles terminate once the taint set stabilises.
//! - **Resumable:** the worklist can be sliced into bounded chunks
//!   ([`InterTaintConfig::budget`]) and resumed to a fixed point by
//!   callers that need complete flow evidence.
//!
//! ## Remaining approximations
//!
//! - Return-value taint is summary-driven. When an adapter emits
//!   `Assign.source_call`, the pass propagates through callee return
//!   summaries only after semantic callee resolution.
//! - Unknown side-effectful calls are not treated as taint flows;
//!   they need explicit source/sink/sanitizer or summary models.
//!
//! ## Tainting predicates — when to use which
//!
//! Seven predicates exist; their differences are load-bearing for
//! precision and easy to confuse. Use them by intent:
//!
//! - [`call_arg_is_directly_tainted`] — strict. True iff the arg's
//!   value text is itself a tainted token.
//! - [`arg_text_has_mapped_descendant_taint`] — true iff the arg
//!   carries a tainted descendant field (`obj.cmd` when `obj.cmd` is
//!   tainted). Adds carrier args to
//!   `args_to_propagate_into_callee` so field-of-carrier flows like
//!   `client.argv` → `param.argv` work without scalar-tainting
//!   `param`.
//! - `arg_text_is_tainted` — relaxed. Walks identifier tokens with
//!   sigil-aware fallbacks. Used only for *receiver* expressions and
//!   for the legacy-call-arg path; never for primary call-arg
//!   tainting decisions because it would re-create the bare-token
//!   over-taint regressions pinned by `over_taint_matrix`.
//! - [`rhs_operand_is_tainted`] — strict. The assignment-RHS
//!   counterpart of `call_arg_is_directly_tainted`. No token-walk
//!   fallback, so `x = "user"` does not taint `x` even when a token
//!   named `user` is in state.
//! - `call_arg_is_tainted` — call-argument wrapper. Checks the raw
//!   argument text plus adapter-emitted operand facts such as
//!   interpolation children. It does not parse interpolation syntax
//!   from string text.
//! - `call_arg_has_direct_value_taint` — diagnostic call-arg wrapper.
//!   Uses strict direct value-text taint plus adapter-emitted operand
//!   facts when deciding which args to record as `tainted_at_call`.
//! - [`receiver_expr_is_tainted`] — receiver-only check. Allows
//!   member access taint propagation into method calls
//!   (`tainted_obj.method(...)` propagates through the receiver) but
//!   does not unconditionally promote receiver taint to scalar arg
//!   taint.
//!
//! ## Diagnostic vs propagation arg sets
//!
//! `propagate_call_event` builds two disjoint-but-overlapping sets:
//!
//! - `tainted_at_call` — direct value taint only. This is what the
//!   user sees in `TaintedCall.tainted_args` and is the only set
//!   considered by `apply_unresolved_call_side_effects` for the
//!   out-param convention.
//! - `args_to_propagate_into_callee` — superset that adds field-of-
//!   carrier args. Used when binding caller args to callee parameter
//!   names so field-to-field mapping is preserved without inflating
//!   the diagnostic surface.
//!
//! Conflating these caused the lifecycle/carrier overtaint family of
//! regressions; see `over_taint_matrix` invariants 7–10.

use crate::{
    intra::intraprocedural_taint,
    text::{
        is_quoted_literal, normalise_qualified_text, qualified_access_bases, qualified_accesses,
        text_looks_qualified, value_bearing_identifier_text,
    },
    IntraTaintResult, TaintConfig, TokenSet,
};
mod summary;
mod summary_impl;

// `pub` (not `pub(crate)`) because `crate::lib` re-exports these
// types as part of the crate's public API. `unreachable_pub` warns
// because `inter` itself is `pub(crate)`, but the lib.rs `pub use
// inter::FunctionSummary` chain requires `pub` here.
#[allow(unreachable_pub)]
pub use summary::{
    function_summary, FunctionSummary, ParamSideEffect, ReturnAccessPath, ReturnElementTaint,
    ReturnFieldTaint,
};

pub(super) use summary_impl::compute_function_summary;
use summary_impl::{access_alias_keys, implicit_receiver_return_is_tainted, receiver_state_names_for_decl};

use ahash::{AHashMap, AHashSet};
use bonsai_callgraph::EdgeKind;
use bonsai_common::{callable_reference_variants, FileId, FuncId, Precision, Span, SymbolId};
use bonsai_db::AnalyzerDb;
use bonsai_lang_api::kit::{callable_param_names_from_text, SYNTHETIC_VARARGS_PARAM};
use bonsai_lang_api::ModulePath;
use bonsai_lang_api::{AliasTarget, CallArg, CallKind, Decl, DeclKind, FlowEvent};
use bonsai_resolve::{
    alias_map_for_file, callee_without_call_args, collect_method_candidates_for_class,
    enclosing_class_for_decl, export_name_variants, extend_alias_targets_with_declared_types,
    is_super_receiver_with_tokens, module_target_matches_decl_module_path, module_target_matches_path,
    namespace_alias_target_tail, prune_receiver_type_names_for_dispatch, push_unique_func,
    qualified_module_alias_call, resolve_callable_with_context, resolve_class, short_tail,
    split_qualified_head_tail, visibility_allows, ResolveContext,
};
use std::borrow::Cow;

/// Configuration knobs for an interprocedural run.
#[derive(Clone, Debug)]
pub struct InterTaintConfig {
    /// Compatibility field retained for callers that still pass a
    /// sanitizer list. Sanitizers are classification evidence, not a
    /// taint-transfer input, so this set does not alter propagation.
    pub sanitizers: TokenSet,
    /// Max distinct `(func, seed)` pairs analyzed in one worklist
    /// chunk before returning a continuation. Default 512. Each pair
    /// is one intraprocedural run, which is bounded itself.
    /// To-completion drivers resume chunks until the semantic
    /// worklist drains, so this controls scheduling granularity
    /// rather than result completeness.
    pub budget: u32,
    /// Optional per-function intraprocedural worklist cap. When unset,
    /// the intraprocedural engine derives a cap from CFG size.
    pub intra_worklist_cap: Option<u32>,
    /// Functions that the security layer has matched as source-bearing
    /// (a source rule fires somewhere in their body). When the engine
    /// processes `var = helper()` and `helper`'s FuncId is in this
    /// set, the assignment LHS is tainted automatically — even if
    /// the engine's call-time state is empty. This closes the
    /// cross-file recall regression for source-bearing helpers
    /// without violating the engine's "empty seed produces no
    /// propagation" invariant: the set is empty by default, so the
    /// engine alone never invents taint.
    pub source_bearing_functions: AHashSet<FuncId>,
    /// Declarative call shapes whose output argument is overwritten
    /// with clean data when every configured value input is clean.
    ///
    /// The common engine deliberately stores no API names here. Callers
    /// that want library-specific modeling must supply these facts from
    /// a rulepack, adapter, or higher-level configuration.
    pub clean_output_overwrites: Vec<CleanOutputOverwrite>,
    /// Declarative source calls whose listed output arguments receive
    /// untrusted data. Used to suppress the generic unresolved-call
    /// side-effect heuristic for calls like `recv(fd, buf, len)`: the
    /// output buffer is tainted by the source, but the fd/len operands
    /// are not.
    pub source_output_args: Vec<SourceOutputArgs>,
    /// Declarative call-result passthroughs supplied by the rulepack.
    /// A configured call maps taint from selected call arguments or the
    /// method receiver to the call return without baking API names into
    /// the IDG core.
    pub call_result_passthroughs: Vec<CallResultPassthrough>,
    /// Declarative output-argument transfer shapes supplied by the
    /// rulepack. A configured call maps taint from selected value
    /// arguments into an addressable output argument without embedding
    /// library API names in the engine.
    pub output_arg_flows: Vec<OutputArgFlow>,
    /// Configured method tails that invoke a callable receiver. Kept
    /// outside the engine so `call`, `apply`, framework-specific names,
    /// etc. are not baked into the common taint transfer logic.
    pub callback_invocation_methods: AHashSet<String>,
    /// Configured receiver-state mutators that move tainted arguments
    /// into the call receiver, such as `Statement.addBatch(sql)` before
    /// `executeBatch()` or `ProcessBuilder.command(cmd)` before
    /// `start()`. Empty by default; security rulepacks supply exact
    /// semantic shapes from `taint_semantics.taint_receiver_from_args`.
    pub receiver_state_propagations: Vec<ReceiverStatePropagation>,
    /// Maximum edge precision for IDG-backed callers. Defaults to the
    /// semantic ceiling (`Precision::Narrowed`) so public taint callers
    /// cannot accidentally emit over-approximate evidence. Legacy
    /// interprocedural callers ignore this field.
    pub max_edge_precision: Option<Precision>,
    /// Which lattice the run should track. `TokenSet` (default) keeps
    /// today's behavior. `Provenance` additionally records value-flow
    /// edges for consumer query (forward / backward closure, paths).
    /// See `crate::value_flow` and ADR 0003.
    pub lattice_mode: crate::value_flow::LatticeMode,
}

/// Declarative clean-output overwrite shape for a configured call.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CleanOutputOverwrite {
    pub callee: String,
    pub output_arg_index: usize,
    pub value_start_arg_index: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceOutputArgs {
    pub callee: String,
    pub output_arg_indices: Vec<usize>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CallResultPassthrough {
    pub callee: String,
    pub input_arg_indices: Vec<usize>,
    pub input_receiver: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutputArgFlow {
    pub callee: String,
    pub output_arg_index: usize,
    pub value_start_arg_index: Option<usize>,
    pub value_arg_indices: Vec<usize>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReceiverStatePropagation {
    pub method: String,
    pub receiver_type: Option<String>,
}

/// Reusable resolver-side caches for batches of interprocedural taint
/// runs over the same workspace snapshot.
///
/// A single `security taint-analysis` command may run the taint engine
/// for hundreds of source scopes. The semantic taint work should vary
/// by seed, but parsing a file and rebuilding its import alias map does
/// not. Callers that batch runs should keep one cache and pass it to
/// [`interprocedural_taint_with_caches`].
///
/// All fields are interior-mutable behind `parking_lot::RwLock` so
/// the entire cache surface can be shared across threads via `&self`
/// — the per-source loop in the security analysis layer parallelises
/// over OWASP's 2,740 source functions, and each source's
/// inter-taint walk concurrently fills these caches with results
/// that are pure functions of static AST state. Cache-fill races on
/// the same key produce identical values (engine purity), so the
/// "loser" computation is wasted work but never wrong.
///
/// **No entry cap.** These caches grow with workspace size; on
/// extremely large workspaces (millions of functions) their RAM
/// footprint is non-trivial but the trade — never recompute a
/// summary you've already paid for — is worth it for analysis
/// throughput. The per-function output caches (`DataFlowCache`,
/// `ValueFlowCache`, etc.) are the ones that get the disk-backed
/// treatment; this cache stays in-memory because every entry is on
/// the hot path of the engine's worklist.
#[derive(Debug, Default)]
pub struct InterTaintCaches {
    aliases_by_file: parking_lot::RwLock<AHashMap<FileId, AHashMap<String, String>>>,
    alias_targets_by_func: parking_lot::RwLock<AHashMap<FuncId, AHashMap<String, AliasTarget>>>,
    local_bindings_by_func: parking_lot::RwLock<AHashMap<FuncId, AHashMap<String, FuncId>>>,
    summaries_by_func: parking_lot::RwLock<AHashMap<FuncId, FunctionSummary>>,
    /// Memo cache for `resolve_call_candidates_with_caller_at`.
    /// Receiver types are part of the key because typed method
    /// dispatch and untyped expression dispatch can produce different
    /// correct answers for the same source span. The result still does
    /// not depend on which source seeded the analysis. Without this
    /// cache, OWASP's 2,740 separate inter-taint runs each re-resolve
    /// the same `String.format(...)` / `Logger.info(...)` call sites
    /// from scratch.
    pub(crate) resolved_calls_by_site: ResolvedCallSiteCache,
}

impl InterTaintCaches {
    /// Drop every cached entry. Workspace-level callers invoke this
    /// when an edit invalidates the underlying static AST state — for
    /// example after `Workspace::ingest_dir` re-writes a file's text.
    pub fn clear(&self) {
        self.aliases_by_file.write().clear();
        self.alias_targets_by_func.write().clear();
        self.local_bindings_by_func.write().clear();
        self.summaries_by_func.write().clear();
        self.resolved_calls_by_site.write().clear();
    }

    /// True iff every cache map is empty. Used by tests to verify
    /// invalidation hooks fire.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.aliases_by_file.read().is_empty()
            && self.alias_targets_by_func.read().is_empty()
            && self.local_bindings_by_func.read().is_empty()
            && self.summaries_by_func.read().is_empty()
            && self.resolved_calls_by_site.read().is_empty()
    }
}

/// Memo store keyed on `(caller_func, call_span, receiver_types)` →
/// resolved callees. `parking_lot::RwLock` for the same reason the four
/// sibling caches use it: read-mostly access pattern under the
/// parallel `flat_map_iter` per-source loop in
/// `build_findings_chain_aware`. Earlier shape was `Mutex` and
/// serialised every per-call-site lookup.
pub(crate) type ResolvedCallSiteCache =
    parking_lot::RwLock<AHashMap<(FuncId, Span, Vec<String>), std::sync::Arc<[ResolvedCallee]>>>;

/// Read-or-fill helper for the RwLock-backed engine caches.
/// Standard double-checked-locking pattern: probe with a read lock
/// first (the common case post-warmup), upgrade to write only on
/// miss. Two threads racing on the same key may both run `init()`
/// — the second writer's `entry().or_insert_with` short-circuits
/// to the first winner so the cached value is single-source-of-truth
/// even under contention.
fn cache_or_insert_with<K, V, F>(map: &parking_lot::RwLock<AHashMap<K, V>>, key: K, init: F) -> V
where
    K: std::hash::Hash + Eq + Clone,
    V: Clone,
    F: FnOnce() -> V,
{
    // Bind the cloned hit to a `let` so the read guard's temporary
    // ends at the `;` rather than being extended across the function
    // body. `parking_lot::RwLock` is non-reentrant, so a still-live
    // read guard would deadlock the subsequent `map.write()`.
    let cached = map.read().get(&key).cloned();
    if let Some(existing) = cached {
        return existing;
    }
    let mut write = map.write();
    write.entry(key).or_insert_with(init).clone()
}

impl Default for InterTaintConfig {
    fn default() -> Self {
        Self {
            sanitizers: TokenSet::default(),
            budget: 512,
            intra_worklist_cap: None,
            source_bearing_functions: AHashSet::default(),
            clean_output_overwrites: Vec::new(),
            source_output_args: Vec::new(),
            call_result_passthroughs: Vec::new(),
            output_arg_flows: Vec::new(),
            callback_invocation_methods: AHashSet::default(),
            receiver_state_propagations: Vec::new(),
            max_edge_precision: Some(Precision::Narrowed),
            lattice_mode: crate::value_flow::LatticeMode::default(),
        }
    }
}

/// Output of an interprocedural run.
#[derive(Clone, Debug, Default)]
pub struct InterTaintResult {
    /// Intraprocedural result per `(FuncId, seed-hash)` pair
    /// analyzed. Keyed so callers can look up "what did the
    /// intraprocedural pass produce for function X with entry seed Y?".
    pub per_function: AHashMap<FunctionSeed, IntraTaintResult>,
    /// Chronological log of cross-function taint propagations.
    /// Every entry records one call site in the caller that fed a
    /// tainted argument into a callee's parameter scope.
    pub call_records: Vec<CallPropagation>,
    /// Tainted call sites whose callee could not be resolved to an
    /// in-workspace function. These are the security sink edges
    /// (`system(cmd)`, `exec(sql)`, etc.) that the indexed taint graph
    /// must expose without replaying the engine at query time.
    pub tainted_calls: Vec<TaintedCall>,
    /// Worst precision observed along any traversed resolver edge.
    /// Callers typically fold this into a finding's top-level
    /// precision tag (same `Precision::meet` discipline the inspect
    /// renderer uses).
    pub precision: Precision,
    /// Total `(func, seed)` pairs analyzed.
    pub pairs_analyzed: u32,
    /// `true` when one worklist chunk hit `InterTaintConfig::budget`
    /// before the worklist drained. To-completion drivers resume the
    /// continuation and should normally return `saturated = false`.
    pub saturated: bool,
    /// Remaining work and visited-state needed to continue a
    /// saturated run. `None` means the worklist drained.
    pub continuation: Option<InterTaintContinuation>,
}

/// One pending interprocedural work item.
#[derive(Clone, Debug, Default)]
pub struct InterTaintWorkItem {
    pub func: FuncId,
    pub seed: TokenSet,
    pub dyn_bindings: AHashMap<String, FuncId>,
    pub const_bindings: AHashMap<String, ConstValue>,
    pub lineage: Option<u64>,
    pub lineage_history: AHashSet<FunctionSeedBase>,
}

/// Small cross-call value fact used only for path pruning. This is not
/// general constant propagation; it records booleans and integer-like
/// flags such as `cleanup(c, 1)` so `if (!free_array)` can be skipped.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ConstValue {
    Bool(bool),
    Int(i64),
}

impl ConstValue {
    fn truthy(self) -> bool {
        match self {
            Self::Bool(value) => value,
            Self::Int(value) => value != 0,
        }
    }
}

/// Resume token for an interprocedural run that hit its pair budget.
#[derive(Clone, Debug, Default)]
pub struct InterTaintContinuation {
    pub pending: Vec<InterTaintWorkItem>,
    pub seen: AHashSet<FunctionSeed>,
}

/// Cache key identifying one interprocedural analysis invocation — the
/// function being analyzed, the taint set it was seeded with
/// (represented as a sorted `Vec<String>` so the key is `Hash + Eq`),
/// and the propagation edge that brought the value into that function.
///
/// The lineage is part of the key on purpose. Two call sites can feed
/// the same tainted parameter set into the same function; collapsing
/// them by `(func, seed)` loses one parent_trace_id and later forces
/// report assembly to guess from the call graph. Recursive expansion is
/// still bounded by `lineage_would_reenter_func` before enqueue.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct FunctionSeed {
    pub func: FuncId,
    pub seed: Vec<String>,
    pub consts: Vec<(String, ConstValue)>,
    pub lineage: Option<u64>,
}

impl FunctionSeed {
    fn new(base: FunctionSeedBase, lineage: Option<u64>) -> Self {
        Self {
            func: base.func,
            seed: base.seed,
            consts: base.consts,
            lineage,
        }
    }
}

/// Recursion guard key for one function/seed/value-domain state,
/// intentionally excluding lineage. It is carried per lineage path so
/// diamonds can analyze the same callee seed from two different call
/// sites, while recursive cycles with the same state are widened.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct FunctionSeedBase {
    pub func: FuncId,
    pub seed: Vec<String>,
    pub consts: Vec<(String, ConstValue)>,
}

impl FunctionSeedBase {
    fn new(func: FuncId, seed: &TokenSet, const_bindings: &AHashMap<String, ConstValue>) -> Self {
        let mut sorted: Vec<String> = seed.iter().cloned().collect();
        sorted.sort();
        let mut consts: Vec<(String, ConstValue)> = const_bindings
            .iter()
            .map(|(name, value)| (name.clone(), *value))
            .collect();
        consts.sort();
        Self {
            func,
            seed: sorted,
            consts,
        }
    }
}

/// One record per cross-function propagation. The resolver may map
/// a single call site to multiple candidate callees (Virtual
/// edges); each candidate gets its own [`CallPropagation`].
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct CallPropagation {
    /// Stable trace ID for this propagation edge within one
    /// interprocedural run. Child work items carry this ID so terminal
    /// tainted calls can point back to the exact edge chain that
    /// produced them instead of relying on graph reachability.
    #[serde(default)]
    pub trace_id: u64,
    /// Parent propagation edge, if this edge was reached from another
    /// tainted call. `None` means this edge starts at the source seed.
    #[serde(default)]
    pub parent_trace_id: Option<u64>,
    pub caller: FuncId,
    pub callee: FuncId,
    pub call_span: Span,
    /// The tainted args fed into this call, with their positional
    /// index + source identifier + the callee's parameter name they
    /// landed on.
    pub tainted_args: Vec<TaintedArg>,
    pub edge_kind: EdgeKind,
    pub edge_precision: Precision,
}

/// One tainted argument at one call site.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct TaintedArg {
    /// Positional index into the call's argument list.
    pub index: usize,
    /// The argument's identifier text as it appeared in the caller's
    /// source (e.g. `tainted_x` in `foo(tainted_x)`).
    pub value_text: String,
    /// The parameter name in the callee's scope this taint
    /// propagates onto (e.g. `a` if the callee is `def foo(a):`).
    pub param_name: String,
}

/// One tainted argument observed AT a call site (caller-side view —
/// no callee param resolution required). Distinct from [`TaintedArg`],
/// which is the propagation-side view that includes the callee's
/// parameter name. Carries the syntactic position so the security
/// renderer can show "tainted args: \[N\] value" without re-parsing
/// when [`TaintedCall::kind`] is [`TaintedCallKind::Call`].
///
/// For [`TaintedCallKind::Write`] and [`TaintedCallKind::Return`], `index`
/// is only the diagnostic operand order among the tainted operands that were
/// recorded for that event. It is not a syntactic call-argument index and
/// must not satisfy security `arg_tainted` constraints.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct TaintedArgAtCall {
    pub index: usize,
    pub value_text: String,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct TaintedCall {
    /// Parent propagation edge for the tainted value observed at this
    /// terminal event. `None` means the terminal event is in the source
    /// function itself.
    #[serde(default)]
    pub parent_trace_id: Option<u64>,
    pub caller: FuncId,
    pub name: String,
    pub call_span: Span,
    pub tainted_args: Vec<TaintedArgAtCall>,
    pub tainted_receiver: Option<String>,
    #[serde(default)]
    pub kind: TaintedCallKind,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaintedCallKind {
    #[default]
    Call,
    Write,
    Return,
}

/// Run the interprocedural taint pass starting from `entry_func`
/// with the given `entry_sources` in the entry function's scope.
///
/// `db` supplies the global decl index, per-file alias maps (via
/// the parser's cached tree), and vfs snapshots. All traversal is
/// resolver-driven — no name-based workspace search.
#[must_use]
pub fn interprocedural_taint(
    entry_func: FuncId,
    entry_sources: &TokenSet,
    config: &InterTaintConfig,
    db: &AnalyzerDb,
) -> InterTaintResult {
    let caches = InterTaintCaches::default();
    interprocedural_taint_with_caches(entry_func, entry_sources, config, db, &caches)
}

/// Run interprocedural taint for one budget chunk and return the
/// partial result with a `continuation` token when the worklist
/// hasn't drained.
///
/// This is the *chunked* primitive — every batch consumes
/// `config.budget` worklist items and stops, even mid-fixpoint, so
/// long-running daemon consumers can interleave work or surface
/// progress between chunks. Pair with
/// [`resume_interprocedural_taint_with_caches`] to drive subsequent
/// chunks against the same cache state. Most callers should prefer
/// [`interprocedural_taint_to_completion_with_caches`], which loops
/// the chunked driver to fixpoint internally.
#[must_use]
pub fn interprocedural_taint_with_caches(
    entry_func: FuncId,
    entry_sources: &TokenSet,
    config: &InterTaintConfig,
    db: &AnalyzerDb,
    caches: &InterTaintCaches,
) -> InterTaintResult {
    let worklist = vec![InterTaintWorkItem {
        func: entry_func,
        seed: entry_sources.clone(),
        dyn_bindings: AHashMap::new(),
        const_bindings: AHashMap::new(),
        lineage: None,
        lineage_history: AHashSet::new(),
    }];
    run_interprocedural_worklist(
        InterTaintAccum::default(),
        worklist,
        AHashSet::default(),
        config,
        db,
        caches,
    )
}

/// Continue a previously chunked / saturated interprocedural run
/// using the `continuation` from `previous`. Pair with
/// [`interprocedural_taint_with_caches`]; the
/// `_to_completion_with_caches` wrapper loops both internally for
/// callers that don't need chunked progress.
#[must_use]
pub fn resume_interprocedural_taint_with_caches(
    mut previous: InterTaintResult,
    config: &InterTaintConfig,
    db: &AnalyzerDb,
    caches: &InterTaintCaches,
) -> InterTaintResult {
    let Some(continuation) = previous.continuation.take() else {
        return previous;
    };
    let accum = InterTaintAccum {
        per_function: previous.per_function,
        call_records: previous.call_records,
        tainted_calls: previous.tainted_calls,
        precision: previous.precision,
        pairs_analyzed: previous.pairs_analyzed,
    };
    run_interprocedural_worklist(accum, continuation.pending, continuation.seen, config, db, caches)
}

/// Run until the worklist drains. `config.budget` is the per-chunk
/// size, not a completeness cap; this driver keeps resuming
/// continuations until semantic fixed point.
#[must_use]
pub fn interprocedural_taint_to_completion_with_caches(
    entry_func: FuncId,
    entry_sources: &TokenSet,
    config: &InterTaintConfig,
    db: &AnalyzerDb,
    caches: &InterTaintCaches,
) -> InterTaintResult {
    let mut result = interprocedural_taint_with_caches(entry_func, entry_sources, config, db, caches);
    while result.continuation.is_some() {
        result = resume_interprocedural_taint_with_caches(result, config, db, caches);
    }
    result
}

struct InterTaintAccum {
    per_function: AHashMap<FunctionSeed, IntraTaintResult>,
    call_records: Vec<CallPropagation>,
    tainted_calls: Vec<TaintedCall>,
    precision: Precision,
    pairs_analyzed: u32,
}

impl Default for InterTaintAccum {
    fn default() -> Self {
        Self {
            per_function: AHashMap::new(),
            call_records: Vec::new(),
            tainted_calls: Vec::new(),
            precision: Precision::Exact,
            pairs_analyzed: 0,
        }
    }
}

fn run_interprocedural_worklist(
    accum: InterTaintAccum,
    mut worklist: Vec<InterTaintWorkItem>,
    mut seen: AHashSet<FunctionSeed>,
    config: &InterTaintConfig,
    db: &AnalyzerDb,
    caches: &InterTaintCaches,
) -> InterTaintResult {
    let global = db.global_index();
    let mut per_function = accum.per_function;
    let mut call_records = accum.call_records;
    let mut tainted_calls = accum.tainted_calls;
    let mut precision = accum.precision;
    let mut pairs_analyzed = accum.pairs_analyzed;
    let chunk_start_pairs = pairs_analyzed;
    let chunk_budget = config.budget.max(1);

    while let Some(item) = worklist.pop() {
        let InterTaintWorkItem {
            func,
            seed,
            dyn_bindings,
            const_bindings,
            lineage,
            mut lineage_history,
        } = item;
        let base_key = FunctionSeedBase::new(func, &seed, &const_bindings);
        let key = FunctionSeed::new(base_key.clone(), lineage);
        if seen.contains(&key) {
            continue;
        }
        if pairs_analyzed.saturating_sub(chunk_start_pairs) >= chunk_budget {
            worklist.push(InterTaintWorkItem {
                func,
                seed,
                dyn_bindings,
                const_bindings,
                lineage,
                lineage_history,
            });
            return InterTaintResult {
                per_function,
                call_records,
                tainted_calls,
                precision,
                pairs_analyzed,
                saturated: true,
                continuation: Some(InterTaintContinuation {
                    pending: worklist,
                    seen,
                }),
            };
        }
        seen.insert(key.clone());
        lineage_history.insert(base_key);
        pairs_analyzed += 1;

        // Fetch the function's decl via the resolver-agnostic global
        // index. FuncId → SymbolId is a `u32` alias; `decl_of`
        // returns the Decl if it exists.
        let symbol = SymbolId::new(func.raw());
        let Some(decl) = global.decl_of(symbol).cloned() else {
            continue;
        };

        // Intraprocedural pass on this function with the seeded state.
        let cfg = db.cfg(func);
        let local_config = TaintConfig {
            sources: seed.clone(),
            sanitizers: TokenSet::default(),
            worklist_cap: config.intra_worklist_cap,
        };
        let intra = intraprocedural_taint(&cfg, &local_config);
        // Walk each block's events in order, tracking the per-event
        // taint state so we can ask "what was tainted *at* this call
        // site?". The intraprocedural pass's `block_in` / `block_out` give block
        // boundaries; for call-site precision we need mid-block
        // state, which is just the block's in state transferred
        // event-by-event up to that event.
        let Some(caller_file) = global.declaring_file(symbol) else {
            per_function.insert(key, intra);
            continue;
        };
        let aliases = cache_or_insert_with(&caches.aliases_by_file, caller_file, || {
            alias_map_for_file(&db.imports_for(caller_file))
        });
        let alias_targets = cache_or_insert_with(&caches.alias_targets_by_func, func, || {
            alias_targets_for_decl(&db.imports_for(caller_file), &decl)
        });
        let mut local_bindings = cache_or_insert_with(&caches.local_bindings_by_func, func, || {
            bonsai_callgraph::collect_local_callable_bindings_with_aliases(
                &decl.flow_events,
                &global,
                &decl,
                &alias_targets,
            )
        });
        // Layer in dynamic callback-param bindings from the call
        // site that put us on the worklist. These take precedence
        // over the static (assignment-only) local_bindings since
        // the parameter shadows any outer alias of the same name.
        for (param, callee) in &dyn_bindings {
            local_bindings.insert(param.clone(), *callee);
        }

        let mut state = seed.clone();
        let mut local_callable_body_calls = AHashMap::new();
        // Resolver cache lives on `caches` but is borrowed
        // immutably here (interior-mutable via `RefCell`) so it can
        // share the borrow with the rest of `caches`'s mutable
        // fields used elsewhere in the loop body.
        let resolved_calls_cache = &caches.resolved_calls_by_site;
        let mut ctx = PropagationCtx {
            caller: func,
            config,
            db,
            aliases: &aliases,
            alias_targets: &alias_targets,
            local_bindings: &local_bindings,
            const_bindings: &const_bindings,
            worklist: &mut worklist,
            call_records: &mut call_records,
            tainted_calls: &mut tainted_calls,
            precision: &mut precision,
            current_trace_id: lineage,
            lineage_history: &lineage_history,
            resolved_calls: Some(resolved_calls_cache),
            local_callable_body_calls: &mut local_callable_body_calls,
        };
        propagate_taint_through_events(&decl.flow_events, &mut state, &mut ctx, &caches.summaries_by_func);

        per_function.insert(key, intra);
    }

    InterTaintResult {
        per_function,
        call_records,
        tainted_calls,
        precision,
        pairs_analyzed,
        saturated: false,
        continuation: None,
    }
}

struct PropagationCtx<'a> {
    caller: FuncId,
    config: &'a InterTaintConfig,
    db: &'a AnalyzerDb,
    aliases: &'a AHashMap<String, String>,
    alias_targets: &'a AHashMap<String, AliasTarget>,
    local_bindings: &'a AHashMap<String, FuncId>,
    const_bindings: &'a AHashMap<String, ConstValue>,
    worklist: &'a mut Vec<InterTaintWorkItem>,
    call_records: &'a mut Vec<CallPropagation>,
    tainted_calls: &'a mut Vec<TaintedCall>,
    precision: &'a mut Precision,
    current_trace_id: Option<u64>,
    lineage_history: &'a AHashSet<FunctionSeedBase>,
    /// Resolver memo cache — populated at the top of an inter-taint
    /// run from `InterTaintCaches::resolved_calls_by_site` so every
    /// `Call` event walked during propagation hits the cache instead
    /// of re-resolving `(caller, span)` from scratch.
    resolved_calls: Option<&'a ResolvedCallSiteCache>,
    local_callable_body_calls: &'a mut AHashMap<String, Vec<DeferredCallableBodyCall>>,
}

#[derive(Clone, Debug)]
struct DeferredCallableBodyCall {
    name: String,
    span: Span,
    params: Vec<String>,
    body_args: Vec<String>,
    captured_tainted_args: Vec<TaintedArgAtCall>,
}

fn propagate_taint_through_events(
    events: &[FlowEvent],
    state: &mut TokenSet,
    ctx: &mut PropagationCtx<'_>,
    summary_cache: &parking_lot::RwLock<AHashMap<FuncId, FunctionSummary>>,
) {
    for (event_index, event) in events.iter().enumerate() {
        let suppress_container_taint = assignment_has_precise_field_projection(events, event_index, event);
        let adjacent_source_call_args = adjacent_call_args_for_assignment(events, event_index);
        let split_call_assignment = split_call_assignment_event(events, event_index);
        let destructure_index = destructuring_target_index(events, event_index, event, ctx.db);
        let return_tainted_assignment =
            if let Some((synthetic, split_call_args)) = split_call_assignment.as_ref() {
                apply_return_taint(
                    synthetic,
                    split_call_args,
                    destructure_index,
                    state,
                    ctx.config,
                    ctx.db,
                    ctx.aliases,
                    ctx.alias_targets,
                    ctx.local_bindings,
                    ctx.caller,
                    summary_cache,
                    suppress_container_taint,
                )
            } else {
                apply_return_taint(
                    event,
                    &adjacent_source_call_args,
                    destructure_index,
                    state,
                    ctx.config,
                    ctx.db,
                    ctx.aliases,
                    ctx.alias_targets,
                    ctx.local_bindings,
                    ctx.caller,
                    summary_cache,
                    suppress_container_taint,
                )
            };

        match event {
            FlowEvent::Call {
                name,
                receiver,
                receiver_types,
                call_kind,
                args,
                span,
                ..
            } => {
                apply_clean_output_call_overwrite(name, args, state, ctx.config);
                propagate_call_event(
                    CallEventView {
                        name,
                        receiver: receiver.as_deref(),
                        receiver_types,
                        call_kind: *call_kind,
                        args,
                        span: *span,
                    },
                    state,
                    ctx,
                    summary_cache,
                );
            }
            FlowEvent::Assign {
                target,
                source_name,
                source_call,
                source_call_args,
                source_names,
                span,
                ..
            } => {
                if !suppress_container_taint {
                    record_tainted_write_event(
                        target,
                        source_name.as_deref(),
                        source_call.as_deref(),
                        source_call_args,
                        source_names,
                        *span,
                        state,
                        ctx,
                    );
                    remember_deferred_callable_body_call(
                        target,
                        source_call.as_deref(),
                        source_call_args,
                        source_names,
                        *span,
                        state,
                        ctx,
                    );
                }
            }
            FlowEvent::Return {
                value_text,
                value_name,
                span,
            } => {
                propagate_super_return_event(value_text.as_deref(), value_name.as_deref(), *span, state, ctx);
                record_tainted_return_event(value_text.as_deref(), value_name.as_deref(), *span, state, ctx);
            }
            FlowEvent::Branch {
                condition,
                then_events,
                else_events,
                ..
            } => {
                if let Some(take_then) = evaluate_branch_condition(condition.as_deref(), ctx.const_bindings) {
                    if take_then {
                        propagate_taint_through_events(then_events, state, ctx, summary_cache);
                    } else {
                        propagate_taint_through_events(else_events, state, ctx, summary_cache);
                    }
                    continue;
                }
                // Each branch inherits the pre-branch state via
                // clone, then mutates it (assignments add/remove
                // tokens). The merged post-branch state is the
                // UNION of the two branch post-states — NOT the
                // union of pre-state plus branch post-states.
                // Using `state.extend(then); state.extend(else)`
                // never removes a token added pre-branch even when
                // both branches reassigned it to a clean value, so
                // clean-overwrite precision is broken at the merge
                // (Task #285 repro: `x = source(); if c { x =
                // clean } else { x = clean }; sink(x)` falsely
                // reported because pre-branch `x` was retained in
                // the parent state).
                let mut then_state = state.clone();
                propagate_taint_through_events(then_events, &mut then_state, ctx, summary_cache);
                let mut else_state = state.clone();
                propagate_taint_through_events(else_events, &mut else_state, ctx, summary_cache);
                let mut merged = then_state;
                merged.extend(else_state);
                *state = merged;
                continue;
            }
            FlowEvent::Loop { body, .. } => {
                walk_loop_body_for_propagation(body, state, ctx, summary_cache);
                continue;
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                catch_param,
                catch_types,
                ..
            } => {
                // Two paths leave the try region:
                //   1. body completed normally → finally runs against
                //      the body's post-state.
                //   2. body threw, catch handled it → finally runs
                //      against catch's post-state.
                // Union both finals so taint reaching the post-region
                // includes contributions from either path. Previously
                // the no-exception path was silently dropped (only
                // catch_state propagated).
                let mut body_state = state.clone();
                propagate_taint_through_events(body, &mut body_state, ctx, summary_cache);
                let mut catch_state = body_state.clone();
                if let Some(param) = catch_param.as_deref() {
                    if !param.is_empty()
                        && try_body_throws_tainted_assignable_to(body, &catch_state, catch_types)
                    {
                        catch_state.insert(param.to_string());
                    }
                }
                propagate_taint_through_events(catch_events, &mut catch_state, ctx, summary_cache);
                propagate_taint_through_events(finally_events, &mut body_state, ctx, summary_cache);
                propagate_taint_through_events(finally_events, &mut catch_state, ctx, summary_cache);
                let mut union = body_state;
                union.extend(catch_state);
                *state = union;
                continue;
            }
            FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                let mut body_state = state.clone();
                propagate_taint_through_events(body, &mut body_state, ctx, summary_cache);
                state.extend(body_state);
                continue;
            }
            FlowEvent::Await { value_name, .. } => {
                // `var = await call()` is encoded by the adapter as
                // an Assign{source_call: callee} preceding this
                // event, so the assignment-side taint is already
                // applied. The bare `await expr` form is the
                // remaining case — when `expr` is a tainted
                // identifier, the awaited value re-enters caller
                // state under the same name, which means the
                // existing state already reflects it. The Await
                // event itself doesn't need to mutate state; treat
                // as informational. The `value_name` is consulted
                // by sanitizer/sink rules that anchor on await
                // boundaries (G-class).
                let _ = value_name;
                continue;
            }
            FlowEvent::Yield { value_text, .. } => {
                // Yields surface the suspend-and-emit value at the
                // generator's site. Caller-side taint propagation
                // happens at the consumer (`for x in gen():` or
                // `async for x in stream:`) which the security
                // layer's source-bearing-function set already
                // schedules. Don't mutate caller state here —
                // doing so would propagate generator-internal
                // state into the wrong scope.
                let _ = value_text;
                continue;
            }
            _ => {}
        }

        if !return_tainted_assignment {
            if split_call_assignment.as_ref().is_some_and(|(synthetic, _)| {
                split_call_assignment_consumes_all_tainted_sources(synthetic, state)
                    && !assignment_event_is_iteration_binding(event, ctx.db)
            }) {
                continue;
            }
            if resolved_source_call_assignment(
                event,
                ctx.config,
                ctx.db,
                ctx.aliases,
                ctx.alias_targets,
                ctx.local_bindings,
                ctx.caller,
            ) && !assignment_event_is_iteration_binding(event, ctx.db)
                && !source_call_assignment_has_independent_tainted_source(
                    event,
                    state,
                    Some(ctx.db),
                    Some(ctx.caller),
                )
            {
                continue;
            }
            apply_event_transfer_with_options(
                event,
                state,
                ctx.config,
                Some(ctx.db),
                Some(ctx.caller),
                suppress_container_taint,
            );
        }
    }
}

fn push_call_propagation(
    ctx: &mut PropagationCtx<'_>,
    callee: FuncId,
    call_span: Span,
    tainted_args: Vec<TaintedArg>,
    edge_kind: EdgeKind,
    edge_precision: Precision,
) -> u64 {
    let trace_id = ctx.call_records.len().saturating_add(1) as u64;
    ctx.call_records.push(CallPropagation {
        trace_id,
        parent_trace_id: ctx.current_trace_id,
        caller: ctx.caller,
        callee,
        call_span,
        tainted_args,
        edge_kind,
        edge_precision,
    });
    trace_id
}

fn child_lineage_history(
    ctx: &PropagationCtx<'_>,
    callee: FuncId,
    seed: &TokenSet,
    const_bindings: &AHashMap<String, ConstValue>,
) -> Option<AHashSet<FunctionSeedBase>> {
    let child_key = FunctionSeedBase::new(callee, seed, const_bindings);
    if ctx.lineage_history.contains(&child_key) {
        return None;
    }
    let mut lineage_history = ctx.lineage_history.clone();
    lineage_history.insert(child_key);
    Some(lineage_history)
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct EffectiveCallArg {
    value_text: String,
    name: Option<String>,
    source_names: Vec<String>,
}

impl EffectiveCallArg {
    fn positional(value_text: String) -> Self {
        Self {
            value_text,
            name: None,
            source_names: Vec::new(),
        }
    }

    fn from_call_arg(arg: &CallArg) -> Self {
        Self {
            value_text: arg.value_text.clone(),
            name: arg.name.clone(),
            source_names: arg.source_names.clone(),
        }
    }
}

fn adjacent_call_args_for_assignment(events: &[FlowEvent], event_index: usize) -> Vec<EffectiveCallArg> {
    let Some(FlowEvent::Assign {
        source_call: Some(source_call),
        source_call_args,
        span: assign_span,
        ..
    }) = events.get(event_index)
    else {
        return Vec::new();
    };

    // Some adapters can identify that an assignment's RHS is a call
    // before they can attach the call's positional args to the Assign
    // itself. They still emit the sibling Call event immediately after
    // the assignment, with its args intact. Correlating that adjacent
    // semantic event keeps return summaries positional; falling back
    // to `source_names` would collapse `f(clean, tainted)` into
    // "some operand was tainted" and reintroduce over-taint.
    events
        .iter()
        .skip(event_index + 1)
        .take(3)
        .find_map(|event| match event {
            FlowEvent::Call { name, args, span, .. }
                if call_names_match(source_call, name)
                    && span.file == assign_span.file
                    && span.start >= assign_span.start
                    && !args.is_empty()
                    && (source_call_args.is_empty()
                        || args.len() > source_call_args.len()
                        || args.iter().any(|arg| arg.name.is_some())) =>
            {
                Some(args.iter().map(EffectiveCallArg::from_call_arg).collect())
            }
            _ => None,
        })
        .unwrap_or_default()
}

fn split_call_assignment_event(
    events: &[FlowEvent],
    event_index: usize,
) -> Option<(FlowEvent, Vec<EffectiveCallArg>)> {
    let FlowEvent::Assign {
        target,
        source_call,
        source_call_args,
        source_names,
        span: assign_span,
        ..
    } = events.get(event_index)?
    else {
        return None;
    };
    let call_matches_assignment = |name: &str| {
        source_call
            .as_deref()
            .is_some_and(|callee| call_names_match(callee, name))
            || source_names
                .iter()
                .any(|source| call_names_match(source, name) || call_names_match(source, short_tail(name)))
    };
    let synthesize = |name: &str, args: &[bonsai_lang_api::CallArg], span: Span| {
        (span.file == assign_span.file
            && span.start >= assign_span.start
            && span.end <= assign_span.end
            && !args.is_empty()
            && (source_call_args.is_empty()
                || args.len() > source_call_args.len()
                || args.iter().any(|arg| arg.name.is_some()))
            && call_matches_assignment(name))
        .then(|| {
            (
                FlowEvent::Assign {
                    span: *assign_span,
                    target: target.clone(),
                    source_name: None,
                    source_call: Some(name.to_string()),
                    source_call_args: args.iter().map(|arg| arg.value_text.clone()).collect(),
                    source_names: source_names.clone(),
                    declares_new_binding: false,
                    value_kind: None,
                },
                args.iter().map(EffectiveCallArg::from_call_arg).collect(),
            )
        })
    };

    events
        .iter()
        .skip(event_index + 1)
        .take(3)
        .find_map(|event| match event {
            FlowEvent::Call { name, args, span, .. }
                if source_call
                    .as_deref()
                    .is_none_or(|callee| call_names_match(callee, name)) =>
            {
                synthesize(name, args, *span)
            }
            _ => None,
        })
        .or_else(|| {
            events[..event_index]
                .iter()
                .rev()
                .take(3)
                .find_map(|event| match event {
                    FlowEvent::Call { name, args, span, .. } => synthesize(name, args, *span),
                    _ => None,
                })
        })
}

fn split_call_assignment_consumes_all_tainted_sources(event: &FlowEvent, state: &TokenSet) -> bool {
    let FlowEvent::Assign {
        source_call: Some(source_call),
        source_call_args,
        source_names,
        ..
    } = event
    else {
        return false;
    };
    let mut allowed = TokenSet::default();
    allowed.insert(source_call.to_string());
    allowed.insert(short_tail(source_call).to_string());
    for arg in source_call_args {
        allowed.insert(arg.trim().to_string());
        allowed.insert(normalise_qualified_text(arg));
    }
    source_names.iter().all(|name| {
        !rhs_operand_is_tainted(name, state)
            || allowed.contains(name.trim())
            || allowed.contains(&normalise_qualified_text(name))
    })
}

fn destructuring_target_index(
    events: &[FlowEvent],
    event_index: usize,
    event: &FlowEvent,
    db: &AnalyzerDb,
) -> Option<usize> {
    let FlowEvent::Assign {
        target,
        source_call: Some(_),
        span,
        ..
    } = event
    else {
        return None;
    };
    let text = source_text_for_span(db, *span)?;
    let lhs = assignment_lhs_text(&text)?;
    let bindings = ordered_pattern_bindings(lhs);
    if bindings.len() <= 1 {
        return None;
    }
    let target = comparable_binding_name(target);
    if target.is_empty() {
        return None;
    }
    bindings
        .iter()
        .position(|binding| comparable_binding_name(binding) == target)
        .or_else(|| destructuring_target_index_from_sibling_events(events, event_index, target.as_str()))
}

fn destructuring_target_index_from_sibling_events(
    events: &[FlowEvent],
    event_index: usize,
    target: &str,
) -> Option<usize> {
    let FlowEvent::Assign {
        span, source_call, ..
    } = events.get(event_index)?
    else {
        return None;
    };
    let mut siblings = events
        .iter()
        .filter_map(|candidate| {
            let FlowEvent::Assign {
                target,
                span: candidate_span,
                source_call: candidate_call,
                ..
            } = candidate
            else {
                return None;
            };
            (candidate_span == span && candidate_call == source_call).then_some(target.as_str())
        })
        .collect::<Vec<_>>();
    siblings.dedup();
    if siblings.len() <= 1 {
        return None;
    }
    siblings
        .iter()
        .position(|binding| comparable_binding_name(binding) == target)
}

fn source_text_for_span(db: &AnalyzerDb, span: Span) -> Option<String> {
    db.adapter_context_with(|ctx| {
        let snapshot = ctx.vfs.snapshot(span.file).ok()?;
        let start = usize::try_from(span.start).ok()?;
        let end = usize::try_from(span.end).ok()?;
        snapshot.text.get(start..end).map(str::to_string)
    })
}

fn assignment_lhs_text(text: &str) -> Option<&str> {
    let assignment_idx = find_assignment_operator(text)?;
    let lhs = text[..assignment_idx]
        .rsplit_once("->")
        .map_or(&text[..assignment_idx], |(_, tail)| tail)
        .trim()
        .trim_end_matches(':')
        .trim();
    (!lhs.is_empty()).then_some(lhs)
}

fn find_assignment_operator(text: &str) -> Option<usize> {
    let mut quote: Option<char> = None;
    let mut escaped = false;
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
        if matches!(ch, '\'' | '"' | '`') {
            quote = Some(ch);
            continue;
        }
        if ch != '=' {
            continue;
        }
        let prev = text[..idx].chars().next_back();
        let next = text[idx + ch.len_utf8()..].chars().next();
        if matches!(prev, Some('=' | '!' | '<' | '>' | '-')) || matches!(next, Some('=' | '>')) {
            continue;
        }
        return Some(idx);
    }
    None
}

fn ordered_pattern_bindings(pattern: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut quote: Option<char> = None;
    let mut escaped = false;
    for ch in pattern.chars() {
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
            flush_pattern_binding(&mut current, &mut out);
            quote = Some(ch);
            continue;
        }
        if ch == '_' || ch == '$' || ch == '@' || ch == '%' || ch.is_ascii_alphanumeric() {
            current.push(ch);
        } else {
            flush_pattern_binding(&mut current, &mut out);
        }
    }
    flush_pattern_binding(&mut current, &mut out);
    out
}

fn flush_pattern_binding(current: &mut String, out: &mut Vec<String>) {
    if current.is_empty() {
        return;
    }
    let raw = std::mem::take(current);
    let cleaned = comparable_binding_name(&raw);
    if cleaned.is_empty()
        || cleaned == "_"
        || cleaned.chars().all(|ch| ch.is_ascii_digit())
        || matches!(
            cleaned.as_str(),
            "auto"
                | "const"
                | "do"
                | "false"
                | "in"
                | "let"
                | "local"
                | "my"
                | "nil"
                | "null"
                | "our"
                | "true"
                | "var"
        )
    {
        return;
    }
    out.push(raw);
}

fn comparable_binding_name(name: &str) -> String {
    name.trim()
        .trim_start_matches(['$', '@', '%'])
        .trim_matches(|ch: char| !(ch == '_' || ch.is_ascii_alphanumeric() || matches!(ch, '$' | '@' | '%')))
        .to_string()
}

fn same_identifier_name(left: &str, right: &str) -> bool {
    comparable_binding_name(left) == comparable_binding_name(right)
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
        let candidate = normalise_target_text(candidate_target);
        candidate.starts_with(&prefix)
    })
}

fn assignment_event_is_iteration_binding(event: &FlowEvent, db: &AnalyzerDb) -> bool {
    let FlowEvent::Assign { target, span, .. } = event else {
        return false;
    };
    assignment_span_is_iteration_binding(Some(db), *span, target)
}

fn call_names_match(left: &str, right: &str) -> bool {
    let left = normalise_qualified_text(left);
    let right = normalise_qualified_text(right);
    if left == right {
        return true;
    }
    !left.is_empty() && !right.is_empty() && short_tail(&left) == short_tail(&right)
}

fn walk_loop_body_for_propagation(
    body: &[FlowEvent],
    state: &mut TokenSet,
    ctx: &mut PropagationCtx<'_>,
    summary_cache: &parking_lot::RwLock<AHashMap<FuncId, FunctionSummary>>,
) {
    let worklist_start = ctx.worklist.len();
    let call_records_start = ctx.call_records.len();
    let tainted_calls_start = ctx.tainted_calls.len();
    let mut loop_state = state.clone();
    let mut grew_on_prior_pass = false;
    loop {
        let before_len = loop_state.len();
        let worklist_len = ctx.worklist.len();
        let call_records_len = ctx.call_records.len();
        let tainted_calls_len = ctx.tainted_calls.len();
        let precision_before = *ctx.precision;
        let mut body_state = loop_state.clone();
        propagate_taint_through_events(body, &mut body_state, ctx, summary_cache);
        loop_state.extend(body_state);
        if loop_state.len() == before_len {
            if grew_on_prior_pass {
                ctx.worklist.truncate(worklist_len);
                ctx.call_records.truncate(call_records_len);
                ctx.tainted_calls.truncate(tainted_calls_len);
                *ctx.precision = precision_before;
            }
            break;
        }
        grew_on_prior_pass = true;
    }
    dedup_loop_work_items(ctx.worklist, worklist_start);
    dedup_loop_call_records(ctx.call_records, call_records_start);
    dedup_loop_tainted_calls(ctx.tainted_calls, tainted_calls_start);
    state.extend(loop_state);
}

fn dedup_loop_work_items(items: &mut Vec<InterTaintWorkItem>, start: usize) {
    let mut seen = AHashSet::new();
    let mut deduped = Vec::new();
    for item in items.drain(start..) {
        if seen.insert(work_item_key(&item)) {
            deduped.push(item);
        }
    }
    items.extend(deduped);
}

fn work_item_key(item: &InterTaintWorkItem) -> (u32, Vec<String>, Vec<(String, u32)>) {
    let mut seed: Vec<String> = item.seed.iter().cloned().collect();
    seed.sort();
    let mut dyn_bindings: Vec<(String, u32)> = item
        .dyn_bindings
        .iter()
        .map(|(param, func)| (param.clone(), func.raw()))
        .collect();
    dyn_bindings.sort();
    (item.func.raw(), seed, dyn_bindings)
}

fn dedup_loop_call_records(records: &mut Vec<CallPropagation>, start: usize) {
    let mut seen = AHashSet::new();
    let mut deduped = Vec::new();
    for record in records.drain(start..) {
        if seen.insert(call_record_key(&record)) {
            deduped.push(record);
        }
    }
    records.extend(deduped);
}

type CallRecordKey = (
    u32,
    u32,
    u32,
    u64,
    u64,
    Vec<(usize, String, String)>,
    EdgeKind,
    Precision,
);

fn call_record_key(record: &CallPropagation) -> CallRecordKey {
    let args = record
        .tainted_args
        .iter()
        .map(|arg| (arg.index, arg.value_text.clone(), arg.param_name.clone()))
        .collect();
    (
        record.caller.raw(),
        record.callee.raw(),
        record.call_span.file.raw(),
        record.call_span.start,
        record.call_span.end,
        args,
        record.edge_kind,
        record.edge_precision,
    )
}

fn dedup_loop_tainted_calls(calls: &mut Vec<TaintedCall>, start: usize) {
    let mut seen = AHashSet::new();
    let mut deduped = Vec::new();
    for call in calls.drain(start..) {
        if seen.insert(tainted_call_key(&call)) {
            deduped.push(call);
        }
    }
    calls.extend(deduped);
}

type TaintedCallKey = (
    u32,
    String,
    u32,
    u64,
    u64,
    Vec<(usize, String)>,
    Option<String>,
    u8,
);

fn tainted_call_key(call: &TaintedCall) -> TaintedCallKey {
    let args = call
        .tainted_args
        .iter()
        .map(|arg| (arg.index, arg.value_text.clone()))
        .collect();
    (
        call.caller.raw(),
        call.name.clone(),
        call.call_span.file.raw(),
        call.call_span.start,
        call.call_span.end,
        args,
        call.tainted_receiver.clone(),
        tainted_call_kind_key(&call.kind),
    )
}

fn tainted_call_kind_key(kind: &TaintedCallKind) -> u8 {
    match kind {
        TaintedCallKind::Call => 0,
        TaintedCallKind::Write => 1,
        TaintedCallKind::Return => 2,
    }
}

#[allow(clippy::too_many_arguments)] // stable parameter list — see calling site for shape
fn record_tainted_write_event(
    target: &str,
    source_name: Option<&str>,
    source_call: Option<&str>,
    source_call_args: &[String],
    source_names: &[String],
    span: Span,
    state: &TokenSet,
    ctx: &mut PropagationCtx<'_>,
) {
    if target.is_empty() {
        return;
    }
    let mut tainted_args: Vec<TaintedArgAtCall> = Vec::new();
    fn push_tainted_arg(args: &mut Vec<TaintedArgAtCall>, value: &str) {
        if args.iter().any(|arg| arg.value_text == value) {
            return;
        }
        let index = args.len();
        args.push(TaintedArgAtCall {
            index,
            value_text: value.to_string(),
        });
    }
    let qualified_bases = synthetic_qualified_source_bases(source_names, span, Some(ctx.db));
    let push_if_tainted = |args: &mut Vec<TaintedArgAtCall>, value: &str| {
        if value.is_empty() || !arg_text_is_tainted(value, state) {
            return;
        }
        push_tainted_arg(args, value);
    };
    if let Some(value) = source_name {
        if assignment_source_name_is_value_tainted(
            value,
            &qualified_bases,
            Some(ctx.db),
            Some(ctx.caller),
            state,
        ) {
            push_tainted_arg(&mut tainted_args, value);
        } else if !qualified_bases.contains(&canonical_bare_name(value)) {
            if let Some(mapped) = mapped_descendant_display(value, state) {
                push_tainted_arg(&mut tainted_args, &mapped);
            }
        }
    }
    if let Some(value) = source_call {
        if source_call_rhs_is_tainted(value, source_call_args, source_names, state) {
            push_tainted_arg(&mut tainted_args, value);
        }
    }
    for value in source_call_args {
        push_if_tainted(&mut tainted_args, value);
    }
    for value in source_names {
        if qualified_bases.contains(&canonical_bare_name(value)) {
            continue;
        }
        if assignment_source_name_is_value_tainted(
            value,
            &qualified_bases,
            Some(ctx.db),
            Some(ctx.caller),
            state,
        ) {
            push_if_tainted(&mut tainted_args, value);
        }
    }
    if tainted_args.is_empty() {
        return;
    }
    ctx.tainted_calls.push(TaintedCall {
        parent_trace_id: ctx.current_trace_id,
        caller: ctx.caller,
        name: target.to_string(),
        call_span: span,
        tainted_args,
        tainted_receiver: None,
        kind: TaintedCallKind::Write,
    });
}

fn remember_deferred_callable_body_call(
    target: &str,
    source_call: Option<&str>,
    source_call_args: &[String],
    source_names: &[String],
    span: Span,
    state: &TokenSet,
    ctx: &mut PropagationCtx<'_>,
) {
    let target = target.trim();
    let Some(source_call) = source_call.map(str::trim).filter(|call| !call.is_empty()) else {
        return;
    };
    if target.is_empty() || source_call == target || short_tail(source_call) == target {
        return;
    }
    let captured_tainted_args =
        tainted_assignment_body_call_args(source_call, source_call_args, source_names, state);
    let params = callable_assignment_params(ctx.db, span);
    if params.is_empty() && captured_tainted_args.is_empty() {
        return;
    }
    let mut body_args = source_call_args.to_vec();
    if body_args.is_empty() {
        body_args.extend(
            source_names
                .iter()
                .filter(|name| {
                    let name = name.trim();
                    !name.is_empty()
                        && !same_identifier_name(name, target)
                        && !call_names_match(name, source_call)
                })
                .cloned(),
        );
    }
    ctx.local_callable_body_calls
        .entry(target.to_string())
        .or_default()
        .push(DeferredCallableBodyCall {
            name: source_call.to_string(),
            span,
            params,
            body_args,
            captured_tainted_args,
        });
}

fn callable_assignment_params(db: &AnalyzerDb, span: Span) -> Vec<String> {
    let rhs = assignment_text_parts(db, span)
        .map(|(_, rhs)| rhs)
        .or_else(|| source_text_for_span(db, span));
    rhs.as_deref()
        .map(callable_param_names_from_text)
        .unwrap_or_default()
}

fn tainted_assignment_body_call_args(
    source_call: &str,
    source_call_args: &[String],
    source_names: &[String],
    state: &TokenSet,
) -> Vec<TaintedArgAtCall> {
    let mut out = Vec::new();
    let mut push = |value: &str| {
        let value = value.trim();
        if value.is_empty()
            || call_names_match(value, source_call)
            || !arg_text_is_tainted(value, state)
            || out.iter().any(|arg: &TaintedArgAtCall| arg.value_text == value)
        {
            return;
        }
        out.push(TaintedArgAtCall {
            index: out.len(),
            value_text: value.to_string(),
        });
    };
    for value in source_call_args {
        push(value);
    }
    for value in source_names {
        push(value);
    }
    out
}

fn record_tainted_return_event(
    value_text: Option<&str>,
    value_name: Option<&str>,
    span: Span,
    state: &TokenSet,
    ctx: &mut PropagationCtx<'_>,
) {
    let mut tainted_args: Vec<TaintedArgAtCall> = Vec::new();
    for value in [value_text, value_name].into_iter().flatten() {
        if value.trim().is_empty() || !arg_text_is_tainted(value, state) {
            continue;
        }
        if tainted_args.iter().any(|arg| arg.value_text == value) {
            continue;
        }
        tainted_args.push(TaintedArgAtCall {
            index: tainted_args.len(),
            value_text: value.to_string(),
        });
    }
    if tainted_args.is_empty() {
        return;
    }
    ctx.tainted_calls.push(TaintedCall {
        parent_trace_id: ctx.current_trace_id,
        caller: ctx.caller,
        name: "return".to_string(),
        call_span: span,
        tainted_args,
        tainted_receiver: None,
        kind: TaintedCallKind::Return,
    });
}

struct CallEventView<'a> {
    name: &'a str,
    receiver: Option<&'a str>,
    receiver_types: &'a [String],
    call_kind: bonsai_lang_api::CallKind,
    args: &'a [bonsai_lang_api::CallArg],
    span: Span,
}

fn callable_value_invocation_is_tainted(
    name: &str,
    call_kind: bonsai_lang_api::CallKind,
    effective_receiver: Option<&str>,
    state: &TokenSet,
    local_bindings: &AHashMap<String, FuncId>,
) -> bool {
    if call_kind == bonsai_lang_api::CallKind::Function
        && arg_text_is_tainted(name, state)
        && local_callable_binding_for_text(name, local_bindings).is_some()
    {
        return true;
    }
    effective_receiver.is_some_and(|receiver| {
        receiver_expr_is_tainted(receiver, state)
            && local_callable_binding_for_text(receiver, local_bindings).is_some()
    })
}

fn callable_value_invocation_matches_candidate(
    name: &str,
    call_kind: bonsai_lang_api::CallKind,
    effective_receiver: Option<&str>,
    candidate: FuncId,
    state: &TokenSet,
    local_bindings: &AHashMap<String, FuncId>,
) -> bool {
    if call_kind == bonsai_lang_api::CallKind::Function
        && arg_text_is_tainted(name, state)
        && local_callable_binding_for_text(name, local_bindings) == Some(candidate)
    {
        return true;
    }
    effective_receiver.is_some_and(|receiver| {
        receiver_expr_is_tainted(receiver, state)
            && local_callable_binding_for_text(receiver, local_bindings) == Some(candidate)
    })
}

fn local_callable_binding_for_text(text: &str, local_bindings: &AHashMap<String, FuncId>) -> Option<FuncId> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return None;
    }
    let folded = trimmed.replace("->", ".").replace("::", ".");
    let normalised = normalise_qualified_text(&folded);
    let lookup = if normalised.is_empty() {
        trimmed
    } else {
        normalised.as_str()
    };
    local_bindings
        .get(lookup)
        .or_else(|| local_bindings.get(short_tail(lookup)))
        .copied()
}

fn seed_lexical_callable_capture(
    callee_seed: &mut TokenSet,
    state: &TokenSet,
    call_name: &str,
    effective_receiver: Option<&str>,
) {
    callee_seed.extend(state.iter().cloned());
    remove_callable_marker(callee_seed, call_name);
    if let Some(receiver) = effective_receiver {
        remove_callable_marker(callee_seed, receiver);
    }
}

fn remove_callable_marker(seed: &mut TokenSet, text: &str) {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return;
    }
    seed.remove(trimmed);
    let normalised = normalise_qualified_text(trimmed);
    if !normalised.is_empty() {
        seed.remove(normalised.as_str());
        seed.remove(short_tail(&normalised));
    }
    seed.remove(short_tail(trimmed));
}

fn propagate_deferred_callable_body_invocation(
    call_name: &str,
    effective_receiver: Option<&str>,
    call_args: &[CallArg],
    state: &TokenSet,
    ctx: &mut PropagationCtx<'_>,
) -> bool {
    let Some(binding) = deferred_callable_binding_for_invocation(
        call_name,
        effective_receiver,
        state,
        ctx.local_callable_body_calls,
    ) else {
        return false;
    };
    let body_calls = binding.to_vec();
    let mut invoked = false;
    for body_call in body_calls {
        let tainted_args = deferred_callable_body_tainted_args(&body_call, call_args, state);
        if tainted_args.is_empty() {
            continue;
        }
        ctx.tainted_calls.push(TaintedCall {
            parent_trace_id: ctx.current_trace_id,
            caller: ctx.caller,
            name: body_call.name,
            call_span: body_call.span,
            tainted_args,
            tainted_receiver: None,
            kind: TaintedCallKind::Call,
        });
        invoked = true;
    }
    invoked
}

fn deferred_callable_body_tainted_args(
    body_call: &DeferredCallableBodyCall,
    call_args: &[CallArg],
    caller_state: &TokenSet,
) -> Vec<TaintedArgAtCall> {
    let mut body_state = TokenSet::default();
    for (idx, arg) in call_args.iter().enumerate() {
        if !call_arg_has_direct_value_taint(arg, caller_state)
            && !arg_text_has_mapped_descendant_taint(&arg.value_text, caller_state)
        {
            continue;
        }
        let param = arg
            .name
            .as_deref()
            .and_then(|name| {
                body_call
                    .params
                    .iter()
                    .find(|param| same_identifier_name(param, name))
            })
            .or_else(|| body_call.params.get(idx));
        if let Some(param) = param {
            bind_param_taint(&mut body_state, param, &arg.value_text, caller_state);
        }
    }

    let mut tainted_args = body_call.captured_tainted_args.clone();
    for body_arg in &body_call.body_args {
        if !arg_text_is_tainted(body_arg, &body_state) {
            continue;
        }
        if tainted_args.iter().any(|arg| arg.value_text == *body_arg) {
            continue;
        }
        tainted_args.push(TaintedArgAtCall {
            index: tainted_args.len(),
            value_text: body_arg.clone(),
        });
    }
    tainted_args
}

fn deferred_callable_binding_for_invocation<'a>(
    call_name: &str,
    effective_receiver: Option<&str>,
    _state: &TokenSet,
    local_callable_body_calls: &'a AHashMap<String, Vec<DeferredCallableBodyCall>>,
) -> Option<&'a [DeferredCallableBodyCall]> {
    let mut candidates = Vec::new();
    candidates.push(call_name.trim().to_string());
    if let Some(receiver) = call_receiver_from_name(call_name) {
        candidates.push(receiver);
    }
    if let Some(receiver) = effective_receiver {
        candidates.push(receiver.trim().to_string());
    }
    for candidate in &candidates {
        if candidate.is_empty() {
            continue;
        }
        let normalised = normalise_qualified_text(candidate);
        let lookup = if normalised.is_empty() {
            candidate.as_str()
        } else {
            normalised.as_str()
        };
        if let Some(binding) = local_callable_body_calls
            .get(lookup)
            .or_else(|| local_callable_body_calls.get(short_tail(lookup)))
        {
            return Some(binding.as_slice());
        }
    }
    None
}

fn propagate_call_event(
    call: CallEventView<'_>,
    state: &mut TokenSet,
    ctx: &mut PropagationCtx<'_>,
    summary_cache: &parking_lot::RwLock<AHashMap<FuncId, FunctionSummary>>,
) {
    // Two arg sets, deliberately divergent:
    //   * `tainted_at_call` records args whose direct value is tainted
    //     right now. The direct value can be the raw arg text or an
    //     adapter-emitted operand inside that arg (for example a
    //     parsed string-interpolation expression). Used for diagnostic
    //     bookkeeping and for the unresolved-call out-param convention,
    //     which only fires when prior args are before a directly-tainted slot.
    //   * `args_to_propagate_into_callee` is the superset that also
    //     includes carrier args whose specific field is tainted
    //     (`obj.cmd` when only `obj.cmd` is tainted). Field-of-carrier
    //     args must propagate into the callee parameter map field-to-
    //     field, but they must NOT count as "directly tainted" because
    //     that would re-create the object-wide overtaint we explicitly
    //     reject (see `over_taint_matrix::field_taint_passed_as_carrier_stays_field_scoped`).
    let tainted_at_call: Vec<(usize, String)> = call
        .args
        .iter()
        .enumerate()
        .filter(|(_, arg)| call_arg_has_direct_value_taint(arg, state))
        .map(|(idx, arg)| (idx, arg.value_text.clone()))
        .collect();
    let mut args_to_propagate_into_callee = tainted_at_call.clone();
    let diagnostic_tainted_at_call = tainted_at_call.clone();
    for (idx, arg) in call.args.iter().enumerate() {
        if args_to_propagate_into_callee
            .iter()
            .any(|(existing_idx, _)| *existing_idx == idx)
        {
            continue;
        }
        if arg_text_has_mapped_descendant_taint(&arg.value_text, state) {
            args_to_propagate_into_callee.push((idx, arg.value_text.clone()));
        }
    }
    apply_configured_source_output_args(call.name, call.args, ctx.config, state);
    apply_configured_output_arg_flows(call.name, call.args, ctx.config, state);
    let semantic_taint_added = apply_variadic_runtime_call_semantics(call.name, call.args, state);
    let implicit_receiver = implicit_receiver_from_call_name(
        call.name,
        call.call_kind,
        super_receiver_tokens_for_caller(ctx.db, ctx.caller),
    );
    let effective_receiver = call.receiver.or(implicit_receiver.as_deref());
    let tainted_receiver = effective_receiver
        .filter(|receiver| receiver_expr_is_tainted(receiver, state))
        .map(Cow::Borrowed)
        .or_else(|| {
            effective_receiver
                .filter(|receiver| is_super_receiver_for_caller(ctx.db, ctx.caller, receiver))
                .and_then(|_| caller_implicit_receiver_taint_binding(ctx, state).map(Cow::Owned))
        })
        .or_else(|| {
            (call.receiver.is_none() && implicit_receiver.is_some())
                .then(|| caller_implicit_receiver_taint_binding(ctx, state).map(Cow::Owned))
                .flatten()
        });
    let descendant_receiver = effective_receiver
        .filter(|receiver| {
            tainted_receiver.is_none() && arg_text_has_mapped_descendant_taint(receiver, state)
        })
        .map(Cow::Borrowed);
    let callable_value_invocation = callable_value_invocation_is_tainted(
        call.name,
        call.call_kind,
        effective_receiver,
        state,
        ctx.local_bindings,
    );
    let deferred_callable_body_invoked =
        propagate_deferred_callable_body_invocation(call.name, effective_receiver, call.args, state, ctx);
    if args_to_propagate_into_callee.is_empty()
        && tainted_receiver.is_none()
        && descendant_receiver.is_none()
        && !callable_value_invocation
        && !deferred_callable_body_invoked
        && !semantic_taint_added
    {
        return;
    }

    if let Some(receiver_value) = effective_receiver {
        if !diagnostic_tainted_at_call.is_empty()
            && configured_receiver_state_propagation_matches(
                &ctx.config.receiver_state_propagations,
                call.name,
                call.receiver_types,
            )
        {
            insert_descendant_target_taint(state, receiver_value);
        }
    }

    if let Some(receiver_value) = tainted_receiver.as_deref() {
        propagate_receiver_taint_to_callback_args(receiver_value, call.args, call.span, ctx);
    }

    if !diagnostic_tainted_at_call.is_empty() || tainted_receiver.is_some() {
        ctx.tainted_calls.push(TaintedCall {
            parent_trace_id: ctx.current_trace_id,
            caller: ctx.caller,
            name: call.name.to_string(),
            call_span: call.span,
            tainted_args: diagnostic_tainted_at_call
                .iter()
                .map(|(idx, value)| TaintedArgAtCall {
                    index: *idx,
                    value_text: value.clone(),
                })
                .collect(),
            tainted_receiver: tainted_receiver.as_deref().map(str::to_string),
            kind: TaintedCallKind::Call,
        });
    }

    let resolve_scope = CallResolveScope::from_ctx(ctx);
    let mut candidates = resolve_call_candidates_with_caller_at(
        call.name,
        &resolve_scope,
        call.receiver_types,
        Some(call.span),
    );
    if candidates.is_empty() {
        candidates = resolve_call_event_candidates_via_callgraph(&call, ctx);
        if !candidates.is_empty() {
            if let Some(cache) = ctx.resolved_calls {
                let arc: std::sync::Arc<[ResolvedCallee]> = candidates.iter().cloned().collect();
                cache
                    .write()
                    .insert((ctx.caller, call.span, call.receiver_types.to_vec()), arc);
            }
        }
    }
    if candidates.is_empty() && call.call_kind == CallKind::Function {
        candidates = resolve_c_family_function_call_candidates(call.name, ctx);
        if !candidates.is_empty() {
            if let Some(cache) = ctx.resolved_calls {
                let arc: std::sync::Arc<[ResolvedCallee]> = candidates.iter().cloned().collect();
                cache
                    .write()
                    .insert((ctx.caller, call.span, call.receiver_types.to_vec()), arc);
            }
        }
    }
    let constructor_candidates =
        constructor_candidates_for_class_call(ctx.db, ctx.caller, ctx.alias_targets, call.name);
    if !constructor_candidates.is_empty() {
        candidates.retain(|candidate| {
            ctx.db
                .global_index()
                .decl_of(SymbolId::new(candidate.func.raw()))
                .is_none_or(|decl| !matches!(decl.kind, DeclKind::Class | DeclKind::Struct))
        });
        for candidate in constructor_candidates {
            if !candidates.iter().any(|existing| existing.func == candidate.func) {
                candidates.push(candidate);
            }
        }
        if let Some(cache) = ctx.resolved_calls {
            let arc: std::sync::Arc<[ResolvedCallee]> = candidates.iter().cloned().collect();
            cache
                .write()
                .insert((ctx.caller, call.span, call.receiver_types.to_vec()), arc);
        }
    }
    if candidates.is_empty() {
        return;
    }

    let effective_call_args = call
        .args
        .iter()
        .map(EffectiveCallArg::from_call_arg)
        .collect::<Vec<_>>();
    let candidates =
        narrow_overload_candidates_by_arg_types(candidates, &effective_call_args, ctx.db, ctx.caller);
    if candidates.is_empty() {
        return;
    }

    let global = ctx.db.global_index();
    for candidate in &candidates {
        let Some(callee_decl) = global.decl_of(SymbolId::new(candidate.func.raw())) else {
            continue;
        };
        let summary = cache_or_insert_with(summary_cache, candidate.func, || {
            global
                .decl_of(SymbolId::new(candidate.func.raw()))
                .map(compute_function_summary)
                .unwrap_or_default()
        });
        let mut callee_seed = TokenSet::default();
        let mut record_args: Vec<TaintedArg> = Vec::new();
        let mut tainted_param_indices: Vec<(usize, usize, String)> = Vec::new();
        if callable_value_invocation_matches_candidate(
            call.name,
            call.call_kind,
            effective_receiver,
            candidate.func,
            state,
            ctx.local_bindings,
        ) {
            seed_lexical_callable_capture(&mut callee_seed, state, call.name, effective_receiver);
        }
        let receiver_value_for_binding = tainted_receiver.as_deref().or(descendant_receiver.as_deref());
        if let (Some(receiver_index), Some(receiver_value)) =
            (callee_decl.receiver_param_index, receiver_value_for_binding)
        {
            let Some(param_name) = callee_decl.params.get(receiver_index).cloned() else {
                continue;
            };
            if !param_name.is_empty() {
                bind_param_taint(&mut callee_seed, &param_name, receiver_value, state);
            }
            tainted_param_indices.push((receiver_index, 0, receiver_value.to_string()));
            record_args.push(TaintedArg {
                index: receiver_index,
                value_text: mapped_descendant_display(receiver_value, state)
                    .unwrap_or_else(|| receiver_value.to_string()),
                param_name,
            });
        }
        if callee_decl.receiver_param_index.is_none() {
            if let Some(receiver_value) = receiver_value_for_binding {
                let receiver_state_names = receiver_state_names_for_decl(callee_decl);
                for receiver_seed in &receiver_state_names {
                    if !receiver_seed.is_empty() {
                        bind_param_taint(&mut callee_seed, receiver_seed, receiver_value, state);
                    }
                }
                if !receiver_state_names.is_empty() {
                    record_args.push(TaintedArg {
                        index: 0,
                        value_text: mapped_descendant_display(receiver_value, state)
                            .unwrap_or_else(|| receiver_value.to_string()),
                        param_name: callee_decl
                            .implicit_receiver_names
                            .iter()
                            .find(|name| !name.trim().is_empty())
                            .cloned()
                            .or_else(|| {
                                receiver_state_names
                                    .iter()
                                    .find(|name| !name.trim().is_empty())
                                    .cloned()
                            })
                            .unwrap_or_else(|| receiver_value.to_string()),
                    });
                }
            }
        }
        for (arg_index, value_text) in &args_to_propagate_into_callee {
            // `param_index` is the callee's parameter slot for binding;
            // shifted by 1 when the callee declares an implicit receiver
            // parameter (Rust/Python `self`).
            let param_index = callee_decl
                .receiver_param_index
                .filter(|receiver_index| *arg_index >= *receiver_index)
                .map_or(*arg_index, |_| arg_index + 1);
            let Some(param_name) = callee_decl.params.get(param_index).cloned() else {
                continue;
            };
            if !param_name.is_empty() {
                bind_param_taint(&mut callee_seed, &param_name, value_text, state);
            }
            tainted_param_indices.push((param_index, *arg_index, value_text.clone()));
            // `TaintedArg.index` is the call-site argument slot, NOT
            // the callee parameter index — see the field's docstring
            // (`crates/taint/src/inter.rs` ~line 177). Reviewers and
            // rule authors expect "argument N is tainted" relative to
            // what they wrote in the source. Drift guard:
            // `tainted_args_index_is_call_site_position` in
            // `crates/conformance/tests/architecture_invariants.rs`.
            record_args.push(TaintedArg {
                index: *arg_index,
                value_text: mapped_descendant_display(value_text, state)
                    .unwrap_or_else(|| value_text.clone()),
                param_name,
            });
        }
        apply_resolved_param_side_effects(
            call.args,
            &tainted_param_indices,
            &summary.taints_params_from,
            state,
        );
        // Build callback-param bindings for the call: any arg whose
        // value_text resolves to a workspace function name binds
        // the corresponding callee parameter to that function. Lets
        // the callee resolve `cb(value)` (where `cb` is the
        // parameter name) to the real function on its own worklist
        // iteration, so callback flow propagates taint into the
        // dispatch target. Receiver-aware param-index calculation
        // mirrors the tainted-arg loop above.
        let mut dyn_bindings: AHashMap<String, FuncId> = AHashMap::new();
        let mut callee_consts: AHashMap<String, ConstValue> = AHashMap::new();
        for (arg_index, arg) in call.args.iter().enumerate() {
            let param_index = callee_decl
                .receiver_param_index
                .filter(|receiver_index| arg_index >= *receiver_index)
                .map_or(arg_index, |_| arg_index + 1);
            if let Some(param_name) = callee_decl.params.get(param_index) {
                if !param_name.is_empty() {
                    if let Some(value) = const_value_of_arg(&arg.value_text, ctx.const_bindings) {
                        callee_consts.insert(param_name.clone(), value);
                    }
                }
            }

            let mut callable = None;
            for raw in callable_reference_variants(&arg.value_text) {
                let raw = raw.trim();
                if raw.is_empty() {
                    continue;
                }
                let candidates = resolve_call_candidates_with_caller(
                    raw,
                    ctx.aliases,
                    ctx.alias_targets,
                    ctx.local_bindings,
                    ctx.db,
                    ctx.caller,
                    ctx.config,
                );
                if let Some(func) = unique_narrowed_candidate(&candidates) {
                    callable = Some(func);
                    break;
                }
            }
            let Some(callable) = callable else {
                continue;
            };
            // Don't bind a function to itself — that creates an
            // infinite worklist if `f` happens to be in scope by
            // its own name.
            if callable == candidate.func {
                continue;
            }
            let Some(param_name) = callee_decl.params.get(param_index) else {
                continue;
            };
            if !param_name.is_empty() {
                dyn_bindings.insert(param_name.clone(), callable);
            }
        }
        *ctx.precision = ctx.precision.meet(candidate.precision);
        let trace_id = push_call_propagation(
            ctx,
            candidate.func,
            call.span,
            record_args,
            candidate.kind,
            candidate.precision,
        );
        if let Some(lineage_history) =
            child_lineage_history(ctx, candidate.func, &callee_seed, &callee_consts)
                .filter(|_| !callee_seed.is_empty() || !dyn_bindings.is_empty() || !callee_consts.is_empty())
        {
            ctx.worklist.push(InterTaintWorkItem {
                func: candidate.func,
                seed: callee_seed,
                dyn_bindings,
                const_bindings: callee_consts,
                lineage: Some(trace_id),
                lineage_history,
            });
        }
    }
}

fn apply_variadic_runtime_call_semantics(name: &str, args: &[CallArg], state: &mut TokenSet) -> bool {
    if !call_names_match(name, "va_start") && short_tail(name) != "va_start" {
        return false;
    }
    if !arg_text_is_tainted(SYNTHETIC_VARARGS_PARAM, state) {
        return false;
    }
    let Some(list_arg) = args.first() else {
        return false;
    };
    let target = list_arg.value_text.trim();
    if target.is_empty() {
        return false;
    }
    insert_value_target_taint(state, target);
    true
}

fn resolve_call_event_candidates_via_callgraph(
    call: &CallEventView<'_>,
    ctx: &PropagationCtx<'_>,
) -> Vec<ResolvedCallee> {
    let global = ctx.db.global_index();
    let caller_sym = SymbolId::new(ctx.caller.raw());
    let Some(caller_decl) = global.decl_of(caller_sym) else {
        return Vec::new();
    };
    let caller_export_aliases = global
        .declaring_file(caller_sym)
        .and_then(|file| ctx.db.adapter_for(file))
        .map(|adapter| adapter.capabilities().module_export_aliases)
        .unwrap_or(&[]);
    let caller_super_receiver_tokens = global
        .declaring_file(caller_sym)
        .and_then(|file| ctx.db.adapter_for(file))
        .map(|adapter| adapter.capabilities().effective_super_receiver_tokens())
        .unwrap_or(bonsai_common::SUPER_RECEIVER_TOKENS);
    let targets = bonsai_callgraph::collect_call_event_targets_with_context_aliases_and_super_tokens(
        &global,
        call.name,
        call.receiver,
        call.receiver_types,
        call.call_kind,
        call.span,
        call.args,
        caller_decl,
        ctx.alias_targets,
        &|file| {
            ctx.db
                .vfs()
                .path(file)
                .ok()
                .map(|path| path.to_string_lossy().into_owned())
        },
        caller_export_aliases,
        caller_super_receiver_tokens,
    );
    let receiver_dispatch = call.call_kind == CallKind::Method
        && (call.receiver.is_some()
            || !call.receiver_types.is_empty()
            || call_receiver_from_name(call.name).is_some());
    semantic_callees_from_candidates(targets, receiver_dispatch)
}

fn resolve_c_family_function_call_candidates(name: &str, ctx: &PropagationCtx<'_>) -> Vec<ResolvedCallee> {
    let lookup = normalise_qualified_text(name);
    let lookup = if lookup.is_empty() {
        name.trim()
    } else {
        lookup.trim()
    };
    if !unqualified_c_family_function_name(lookup) {
        return Vec::new();
    }
    let global = ctx.db.global_index();
    let caller_sym = SymbolId::new(ctx.caller.raw());
    let Some(caller_file) = global.declaring_file(caller_sym) else {
        return Vec::new();
    };
    let c_family = ctx
        .db
        .adapter_for(caller_file)
        .map(|adapter| adapter.language_id().as_str())
        .is_some_and(|language| matches!(language, "c" | "cpp" | "objc"));
    if !c_family {
        return Vec::new();
    }
    let Some(caller_decl) = global.decl_of(caller_sym) else {
        return Vec::new();
    };
    let resolve_ctx =
        ResolveContext::new(caller_file, &caller_decl.module_path).with_alias_map(ctx.alias_targets);
    let mut targets = bonsai_callgraph::collect_callable_targets(&global, lookup);
    targets.retain(|func| {
        let sym = SymbolId::new(func.raw());
        let Some(decl) = global.decl_of(sym) else {
            return false;
        };
        let Some(file) = global.declaring_file(sym) else {
            return false;
        };
        visibility_allows(decl, file, &decl.module_path, &resolve_ctx)
    });
    semantic_callees_from_candidates(targets, false)
}

fn unqualified_c_family_function_name(name: &str) -> bool {
    !name.is_empty()
        && !name.contains('.')
        && !name.contains(':')
        && !name.contains('\\')
        && !name.contains("->")
        && !name.contains('(')
        && !name.chars().any(char::is_whitespace)
}

fn propagate_receiver_taint_to_callback_args(
    receiver_value: &str,
    args: &[bonsai_lang_api::CallArg],
    span: Span,
    ctx: &mut PropagationCtx<'_>,
) {
    for arg in args {
        let mut callbacks = Vec::new();
        for callback_name in callable_reference_variants(&arg.value_text) {
            let callback_name = callback_name.trim();
            if callback_name.is_empty() {
                continue;
            }
            callbacks = resolve_call_candidates_with_caller(
                callback_name,
                ctx.aliases,
                ctx.alias_targets,
                ctx.local_bindings,
                ctx.db,
                ctx.caller,
                ctx.config,
            );
            if !callbacks.is_empty() {
                break;
            }
        }
        if callbacks.is_empty() {
            continue;
        }
        let global = ctx.db.global_index();
        for callback in callbacks {
            let Some(callback_decl) = global.decl_of(SymbolId::new(callback.func.raw())) else {
                continue;
            };
            let Some((param_index, param_name)) = first_non_receiver_param(callback_decl) else {
                continue;
            };
            let mut callee_seed = TokenSet::default();
            callee_seed.insert(param_name.clone());
            let trace_id = push_call_propagation(
                ctx,
                callback.func,
                span,
                vec![TaintedArg {
                    index: param_index,
                    value_text: receiver_value.to_string(),
                    param_name,
                }],
                EdgeKind::Indirect,
                callback.precision,
            );
            if let Some(lineage_history) =
                child_lineage_history(ctx, callback.func, &callee_seed, &AHashMap::new())
            {
                ctx.worklist.push(InterTaintWorkItem {
                    func: callback.func,
                    seed: callee_seed,
                    dyn_bindings: AHashMap::new(),
                    const_bindings: AHashMap::new(),
                    lineage: Some(trace_id),
                    lineage_history,
                });
            }
            *ctx.precision = ctx.precision.meet(callback.precision);
        }
    }
}

fn propagate_super_return_event(
    value_text: Option<&str>,
    value_name: Option<&str>,
    span: Span,
    state: &TokenSet,
    ctx: &mut PropagationCtx<'_>,
) {
    if !return_expr_is_super(value_text) && !return_expr_is_super(value_name) {
        return;
    }
    // Receivers we might already have taint state for at the moment
    // a `return super.method(...)` fires: the explicit super-family
    // tokens and the implicit-receiver bare tokens. Taint state keyed
    // on any of these gets carried into the resolved super-method.
    let candidate_receivers = bonsai_common::SUPER_RECEIVER_TOKENS
        .iter()
        .chain(bonsai_common::IMPLICIT_RECEIVER_TOKENS.iter())
        .copied();
    let Some(receiver_value) = candidate_receivers.into_iter().find(|candidate| {
        receiver_expr_is_tainted(candidate, state) || actual_has_descendant_taint(candidate, state)
    }) else {
        return;
    };
    let global = ctx.db.global_index();
    let Some(caller_decl) = global.decl_of(SymbolId::new(ctx.caller.raw())) else {
        return;
    };
    let candidates =
        resolve_super_method_candidates(ctx.db, ctx.caller, ctx.alias_targets, &caller_decl.name);
    if candidates.is_empty() {
        return;
    }
    for func in candidates {
        let Some(callee_decl) = global.decl_of(SymbolId::new(func.raw())) else {
            continue;
        };
        let mut callee_seed = TokenSet::default();
        let receiver_state_names = receiver_state_names_for_decl(callee_decl);
        if receiver_state_names.is_empty() {
            insert_value_target_taint(&mut callee_seed, "self");
        } else {
            for receiver_seed in &receiver_state_names {
                bind_param_taint(&mut callee_seed, receiver_seed, receiver_value, state);
            }
        }
        if callee_seed.is_empty() {
            continue;
        }
        let trace_id = push_call_propagation(
            ctx,
            func,
            span,
            vec![TaintedArg {
                index: 0,
                value_text: receiver_value.to_string(),
                param_name: receiver_state_names
                    .first()
                    .cloned()
                    .unwrap_or_else(|| "self".to_string()),
            }],
            EdgeKind::Direct,
            Precision::Narrowed,
        );
        if let Some(lineage_history) = child_lineage_history(ctx, func, &callee_seed, &AHashMap::new()) {
            ctx.worklist.push(InterTaintWorkItem {
                func,
                seed: callee_seed,
                dyn_bindings: AHashMap::new(),
                const_bindings: AHashMap::new(),
                lineage: Some(trace_id),
                lineage_history,
            });
        }
    }
}

fn return_expr_is_super(value: Option<&str>) -> bool {
    let Some(value) = value else {
        return false;
    };
    let value = trim_outer_parens(value.trim());
    value == "super"
        || value
            .strip_prefix("super")
            .is_some_and(|rest| rest.trim_start().starts_with('('))
}

fn apply_resolved_param_side_effects(
    args: &[bonsai_lang_api::CallArg],
    tainted_param_indices: &[(usize, usize, String)],
    effects: &[ParamSideEffect],
    state: &mut TokenSet,
) {
    if effects.is_empty() || tainted_param_indices.is_empty() {
        return;
    }
    for effect in effects {
        if !tainted_param_indices
            .iter()
            .any(|(param_idx, _, _)| *param_idx == effect.source_param)
        {
            continue;
        }
        let Some(arg) = args.get(effect.target_param) else {
            continue;
        };
        let Some(place) = arg.place.as_deref() else {
            continue;
        };
        let place = place.trim();
        if place.is_empty() || is_quoted_literal(place) {
            continue;
        }
        insert_value_target_taint(state, place);
    }
}

fn apply_clean_output_call_overwrite(
    name: &str,
    args: &[bonsai_lang_api::CallArg],
    state: &mut TokenSet,
    config: &InterTaintConfig,
) {
    let Some(shape) = config
        .clean_output_overwrites
        .iter()
        .find(|shape| configured_name_match(&shape.callee, name))
    else {
        return;
    };
    let Some(output) = args
        .get(shape.output_arg_index)
        .and_then(|arg| arg.place.as_deref())
    else {
        return;
    };
    let output = output.trim();
    if output.is_empty() || is_quoted_literal(output) {
        return;
    }
    let value_args_are_clean = args
        .iter()
        .enumerate()
        .filter(|(idx, _)| *idx >= shape.value_start_arg_index)
        .all(|(_, arg)| !call_arg_is_tainted(arg, state));
    if value_args_are_clean {
        remove_target_taint(state, output);
    }
}

fn apply_configured_source_output_args(
    name: &str,
    args: &[bonsai_lang_api::CallArg],
    config: &InterTaintConfig,
    state: &mut TokenSet,
) {
    for shape in &config.source_output_args {
        if !configured_name_match(&shape.callee, name) {
            continue;
        }
        for &index in &shape.output_arg_indices {
            let Some(arg) = args.get(index) else {
                continue;
            };
            let text = arg.place.as_deref().unwrap_or(arg.value_text.as_str()).trim();
            if text.is_empty() || is_quoted_literal(text) {
                continue;
            }
            insert_value_target_taint(state, text);
            insert_descendant_target_taint(state, text);
        }
    }
}

fn apply_configured_output_arg_flows(
    name: &str,
    args: &[bonsai_lang_api::CallArg],
    config: &InterTaintConfig,
    state: &mut TokenSet,
) {
    for shape in &config.output_arg_flows {
        if !configured_name_match(&shape.callee, name) {
            continue;
        }
        let Some(output) = args.get(shape.output_arg_index).and_then(call_output_arg_target) else {
            continue;
        };
        if output.is_empty() || is_quoted_literal(&output) {
            continue;
        }
        if output_arg_flow_inputs_tainted(shape, args, state) {
            insert_value_target_taint(state, &output);
        }
    }
}

fn output_arg_flow_inputs_tainted(
    shape: &OutputArgFlow,
    args: &[bonsai_lang_api::CallArg],
    state: &TokenSet,
) -> bool {
    shape
        .value_arg_indices
        .iter()
        .copied()
        .chain(
            shape
                .value_start_arg_index
                .into_iter()
                .flat_map(|start| start..args.len()),
        )
        .filter(|index| *index != shape.output_arg_index)
        .any(|index| args.get(index).is_some_and(|arg| call_arg_is_tainted(arg, state)))
}

fn call_output_arg_target(arg: &bonsai_lang_api::CallArg) -> Option<String> {
    arg.place
        .as_deref()
        .filter(|place| !place.trim().is_empty())
        .map(str::trim)
        .map(str::to_string)
        .or_else(|| {
            let text = arg.value_text.trim();
            is_bare_identifier_text(text).then(|| text.to_string())
        })
}

fn configured_name_match(configured: &str, observed: &str) -> bool {
    if let Some(regex) = configured.trim().strip_prefix("regex:") {
        return configured_regex_match(regex, observed);
    }
    let configured = normalise_qualified_text(configured.trim());
    let observed = normalise_qualified_text(observed.trim());
    if configured.is_empty() || observed.is_empty() {
        return false;
    }
    configured == observed || configured == short_tail(&observed)
}

fn configured_regex_match(regex: &str, observed: &str) -> bool {
    let Ok(regex) = regex::Regex::new(regex) else {
        return false;
    };
    let observed = observed.trim();
    if observed.is_empty() {
        return false;
    }
    regex.is_match(observed) || regex.is_match(&normalise_qualified_text(observed))
}

fn configured_tail_match(configured_tails: &AHashSet<String>, observed: &str) -> bool {
    let observed = normalise_qualified_text(observed.trim());
    if observed.is_empty() {
        return false;
    }
    let observed_tail = short_tail(&observed);
    configured_tails.iter().any(|configured| {
        let configured = normalise_qualified_text(configured.trim());
        !configured.is_empty() && (configured == observed || configured == observed_tail)
    })
}

fn configured_receiver_state_propagation_matches(
    configured: &[ReceiverStatePropagation],
    observed: &str,
    receiver_types: &[String],
) -> bool {
    let observed = normalise_qualified_text(observed.trim());
    if observed.is_empty() {
        return false;
    }
    let observed_tail = short_tail(&observed);
    configured.iter().any(|shape| {
        let method = normalise_qualified_text(shape.method.trim());
        if method.is_empty() || (method != observed && method != observed_tail) {
            return false;
        }
        let Some(expected_type) = shape.receiver_type.as_deref() else {
            return true;
        };
        receiver_types
            .iter()
            .any(|actual| type_name_matches_expected(actual, expected_type))
    })
}

fn type_name_matches_expected(actual: &str, expected: &str) -> bool {
    use bonsai_common::ALL_NAME_PUNCTUATION;
    let actual = normalise_qualified_text(actual.trim().trim_start_matches(ALL_NAME_PUNCTUATION));
    let expected = normalise_qualified_text(expected.trim().trim_start_matches(ALL_NAME_PUNCTUATION));
    if actual.is_empty() || expected.is_empty() {
        return false;
    }
    actual == expected || short_tail(&actual) == short_tail(&expected)
}

fn first_non_receiver_param(decl: &Decl) -> Option<(usize, String)> {
    decl.params
        .iter()
        .enumerate()
        .find(|(idx, param)| decl.receiver_param_index != Some(*idx) && !param.is_empty())
        .map(|(idx, param)| (idx, param.clone()))
}

/// Return true when the call or write event at `sink_span` receives a
/// value tainted from `entry_sources` while executing `func`.
///
/// This is the call-site precise predicate used by security mode after
/// it has matched a source and a sink fact. It intentionally answers a
/// narrower question than chain reachability: a sink is confirmed only
/// when one of the matched sink call's arguments, receiver, or write
/// RHS is tainted at that byte span.
#[must_use]
pub fn call_site_receives_taint(
    func: FuncId,
    sink_span: Span,
    entry_sources: &TokenSet,
    config: &InterTaintConfig,
    db: &AnalyzerDb,
) -> bool {
    let caches = InterTaintCaches::default();
    call_site_receives_taint_with_caches(func, sink_span, entry_sources, config, db, &caches)
}

/// Cached variant of [`call_site_receives_taint`] for batched sink
/// verification in one workspace snapshot.
#[must_use]
pub fn call_site_receives_taint_with_caches(
    func: FuncId,
    sink_span: Span,
    entry_sources: &TokenSet,
    config: &InterTaintConfig,
    db: &AnalyzerDb,
    caches: &InterTaintCaches,
) -> bool {
    let global = db.global_index();
    let Some(decl) = global.decl_of(SymbolId::new(func.raw())).cloned() else {
        return false;
    };
    let Some(file) = global.declaring_file(SymbolId::new(func.raw())) else {
        return false;
    };
    let aliases = cache_or_insert_with(&caches.aliases_by_file, file, || {
        alias_map_for_file(&db.imports_for(file))
    });
    let alias_targets = cache_or_insert_with(&caches.alias_targets_by_func, func, || {
        alias_targets_for_decl(&db.imports_for(file), &decl)
    });
    let local_bindings = cache_or_insert_with(&caches.local_bindings_by_func, func, || {
        bonsai_callgraph::collect_local_callable_bindings_with_aliases(
            &decl.flow_events,
            &global,
            &decl,
            &alias_targets,
        )
    });
    let const_bindings = AHashMap::new();
    let ctx = SinkWalkCtx {
        sink_span,
        config,
        db,
        aliases: &aliases,
        alias_targets: &alias_targets,
        local_bindings: &local_bindings,
        const_bindings: &const_bindings,
        caller: func,
    };
    let (_, found) = walk_events_for_sink(
        &decl.flow_events,
        entry_sources.clone(),
        &ctx,
        &caches.summaries_by_func,
    );
    found
}

struct SinkWalkCtx<'a> {
    sink_span: Span,
    config: &'a InterTaintConfig,
    db: &'a AnalyzerDb,
    aliases: &'a AHashMap<String, String>,
    alias_targets: &'a AHashMap<String, AliasTarget>,
    local_bindings: &'a AHashMap<String, FuncId>,
    const_bindings: &'a AHashMap<String, ConstValue>,
    caller: FuncId,
}

fn walk_events_for_sink(
    events: &[FlowEvent],
    mut state: TokenSet,
    ctx: &SinkWalkCtx<'_>,
    summary_cache: &parking_lot::RwLock<AHashMap<FuncId, FunctionSummary>>,
) -> (TokenSet, bool) {
    for (event_index, event) in events.iter().enumerate() {
        let suppress_container_taint = assignment_has_precise_field_projection(events, event_index, event);
        let adjacent_source_call_args = adjacent_call_args_for_assignment(events, event_index);
        let split_call_assignment = split_call_assignment_event(events, event_index);
        let destructure_index = destructuring_target_index(events, event_index, event, ctx.db);
        let return_tainted_assignment =
            if let Some((synthetic, split_call_args)) = split_call_assignment.as_ref() {
                apply_return_taint(
                    synthetic,
                    split_call_args,
                    destructure_index,
                    &mut state,
                    ctx.config,
                    ctx.db,
                    ctx.aliases,
                    ctx.alias_targets,
                    ctx.local_bindings,
                    ctx.caller,
                    summary_cache,
                    suppress_container_taint,
                )
            } else {
                apply_return_taint(
                    event,
                    &adjacent_source_call_args,
                    destructure_index,
                    &mut state,
                    ctx.config,
                    ctx.db,
                    ctx.aliases,
                    ctx.alias_targets,
                    ctx.local_bindings,
                    ctx.caller,
                    summary_cache,
                    suppress_container_taint,
                )
            };
        if event_at_sink_receives_taint(event, ctx.sink_span, &state) {
            return (state, true);
        }
        match event {
            FlowEvent::Branch {
                condition,
                then_events,
                else_events,
                ..
            } => {
                if let Some(take_then) = evaluate_branch_condition(condition.as_deref(), ctx.const_bindings) {
                    return if take_then {
                        walk_events_for_sink(then_events, state, ctx, summary_cache)
                    } else {
                        walk_events_for_sink(else_events, state, ctx, summary_cache)
                    };
                }
                let (then_state, then_found) =
                    walk_events_for_sink(then_events, state.clone(), ctx, summary_cache);
                if then_found {
                    return (then_state, true);
                }
                let (else_state, else_found) =
                    walk_events_for_sink(else_events, state.clone(), ctx, summary_cache);
                if else_found {
                    return (else_state, true);
                }
                let mut merged = then_state;
                merged.extend(else_state);
                state = merged;
                continue;
            }
            FlowEvent::Loop { body, .. } => {
                let (loop_state, loop_found) =
                    walk_loop_body_for_sink(body, state.clone(), ctx, summary_cache);
                if loop_found {
                    return (loop_state, true);
                }
                state.extend(loop_state);
                continue;
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                catch_param,
                catch_types,
                ..
            } => {
                let (body_state, body_found) = walk_events_for_sink(body, state.clone(), ctx, summary_cache);
                if body_found {
                    return (body_state, true);
                }
                let mut catch_input = body_state;
                if let Some(param) = catch_param.as_deref() {
                    if !param.is_empty()
                        && try_body_throws_tainted_assignable_to(body, &catch_input, catch_types)
                    {
                        catch_input.insert(param.to_string());
                    }
                }
                let (catch_state, catch_found) =
                    walk_events_for_sink(catch_events, catch_input, ctx, summary_cache);
                if catch_found {
                    return (catch_state, true);
                }
                let (finally_state, finally_found) =
                    walk_events_for_sink(finally_events, catch_state, ctx, summary_cache);
                if finally_found {
                    return (finally_state, true);
                }
                state = finally_state;
                continue;
            }
            FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                let (body_state, body_found) = walk_events_for_sink(body, state.clone(), ctx, summary_cache);
                if body_found {
                    return (body_state, true);
                }
                state.extend(body_state);
                continue;
            }
            _ => {}
        }
        if !return_tainted_assignment {
            if split_call_assignment.as_ref().is_some_and(|(synthetic, _)| {
                split_call_assignment_consumes_all_tainted_sources(synthetic, &state)
                    && !assignment_event_is_iteration_binding(event, ctx.db)
            }) {
                continue;
            }
            if let FlowEvent::Call { name, args, .. } = event {
                apply_configured_source_output_args(name, args, ctx.config, &mut state);
                apply_configured_output_arg_flows(name, args, ctx.config, &mut state);
                let candidates = resolve_call_candidates_with_caller(
                    name,
                    ctx.aliases,
                    ctx.alias_targets,
                    ctx.local_bindings,
                    ctx.db,
                    ctx.caller,
                    ctx.config,
                );
                if candidates.is_empty() {
                    continue;
                }
            }
            if resolved_source_call_assignment(
                event,
                ctx.config,
                ctx.db,
                ctx.aliases,
                ctx.alias_targets,
                ctx.local_bindings,
                ctx.caller,
            ) && !assignment_event_is_iteration_binding(event, ctx.db)
                && !source_call_assignment_has_independent_tainted_source(
                    event,
                    &state,
                    Some(ctx.db),
                    Some(ctx.caller),
                )
            {
                continue;
            }
            apply_event_transfer_with_options(
                event,
                &mut state,
                ctx.config,
                Some(ctx.db),
                Some(ctx.caller),
                suppress_container_taint,
            );
        }
    }
    (state, false)
}

fn walk_loop_body_for_sink(
    body: &[FlowEvent],
    state: TokenSet,
    ctx: &SinkWalkCtx<'_>,
    summary_cache: &parking_lot::RwLock<AHashMap<FuncId, FunctionSummary>>,
) -> (TokenSet, bool) {
    let mut loop_state = state;
    loop {
        let before_len = loop_state.len();
        let (body_state, body_found) = walk_events_for_sink(body, loop_state.clone(), ctx, summary_cache);
        if body_found {
            return (body_state, true);
        }
        loop_state.extend(body_state);
        if loop_state.len() == before_len {
            return (loop_state, false);
        }
    }
}

fn try_body_throws_tainted(events: &[FlowEvent], state: &TokenSet) -> bool {
    // Walk the body forward maintaining a local mirror of the taint
    // state so an Assign before the Throw (e.g. `e = ValueError(cmd);
    // raise e`) is observed when checking whether the throw value
    // is tainted. Without this stateful walk, `raise e` shows up
    // with `value_name: Some("e")` but `e` was only entered into
    // state by the preceding Assign, which the static check missed.
    let mut local_state = state.clone();
    try_body_throws_tainted_with_state(events, &mut local_state)
}

/// Type-aware variant of `try_body_throws_tainted`. Returns true iff
/// at least one body throw is both tainted *and* plausibly catchable
/// by the catch arm's declared types.
///
/// Resolution rules, in order:
///
///   1. `catch_types` empty → adapter didn't surface type info
///      (catch-all `catch { }`, Python `except:`, etc.). Fall back to
///      conservative "seed if any tainted throw" rule.
///   2. Any catch type is a known root-of-hierarchy (`Exception`,
///      `Throwable`, `Error`, `RuntimeException`, `System.Exception`)
///      → conservative seed. Without the JVM/CLR class hierarchy we
///      can't prove `IOException` is a subtype of `Exception`, but at
///      the language level `catch (Exception e)` catches every
///      throwable.
///   3. Otherwise: exact-name matching of `thrown_type` against a
///      catch arm. Throws whose `thrown_type` is `None` fall back to
///      conservative behavior (we don't know the type, so we can't
///      prove the catch can't catch it).
///
/// Adapters canonicalize type names (`canonical_type_name`) so
/// `java.io.IOException` and `IOException` compare equal. A real
/// subtype-aware check would require the language's class hierarchy;
/// that's out of scope.
fn try_body_throws_tainted_assignable_to(
    events: &[FlowEvent],
    state: &TokenSet,
    catch_types: &[String],
) -> bool {
    if catch_types.is_empty() || catch_types.iter().any(|t| is_root_exception_type(t)) {
        return try_body_throws_tainted(events, state);
    }
    let mut local_state = state.clone();
    try_body_throws_tainted_assignable_with_state(events, &mut local_state, catch_types)
}

/// Names of the absolute-root exception types in our supported
/// languages. A `catch (Exception e)` / `catch (Throwable e)` arm in
/// Java/Kotlin/C# catches every thrown subtype; without the language
/// type hierarchy we can't prove subtype relationships any narrower
/// than this. Sub-roots like `RuntimeException` are *not* included
/// here because they don't catch checked exceptions
/// (`IOException`/`SQLException`/etc.) — treating them as
/// catch-anything would re-introduce the over-taint we're trying to
/// remove. Users can still trigger the conservative path explicitly
/// with `catch (Exception e)` or `catch (Throwable e)`.
fn is_root_exception_type(name: &str) -> bool {
    matches!(
        name,
        "Exception" | "Throwable" | "Error" | "System.Exception" | "Object"
    )
}

fn try_body_throws_tainted_assignable_with_state(
    events: &[FlowEvent],
    state: &mut TokenSet,
    catch_types: &[String],
) -> bool {
    for event in events {
        match event {
            // Assign events update the live taint state in lock-step
            // with the body walk so a `t = tainted; throw IO(t)` shape
            // sees `t` as tainted at the throw point.
            FlowEvent::Assign { .. } => {
                let propagation_cfg = InterTaintConfig {
                    sanitizers: TokenSet::default(),
                    budget: 0,
                    intra_worklist_cap: None,
                    ..Default::default()
                };
                apply_event_transfer(event, state, &propagation_cfg, None, None);
            }
            FlowEvent::Throw {
                value_name,
                thrown_type,
                ..
            } => {
                // Decide whether the throw carries taint:
                // - bare-identifier throw (`throw e`) → check `e` directly.
                // - compound throw (`throw new Foo(t)`) → conservative:
                //   any live taint could have been incorporated.
                let throw_carries_taint = match value_name.as_deref() {
                    Some(thrown_name) if !thrown_name.is_empty() => arg_text_is_tainted(thrown_name, state),
                    _ => !state.is_empty(),
                };
                if !throw_carries_taint {
                    continue;
                }
                // Decide whether the throw is catchable by an arm:
                // - thrown_type known → exact-match against catch_types.
                // - unknown → conservative seed (we can't prove it isn't
                //   one of the caught types).
                match thrown_type.as_deref() {
                    Some(known_thrown) => {
                        if catch_types.iter().any(|caught| caught == known_thrown) {
                            return true;
                        }
                    }
                    None => return true,
                }
            }
            // Branches fork state per arm (path sensitivity); union
            // back at the merge so subsequent throws see both arms'
            // contributions.
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                let mut then_state = state.clone();
                if try_body_throws_tainted_assignable_with_state(then_events, &mut then_state, catch_types) {
                    return true;
                }
                let mut else_state = state.clone();
                if try_body_throws_tainted_assignable_with_state(else_events, &mut else_state, catch_types) {
                    return true;
                }
                state.extend(then_state);
                state.extend(else_state);
            }
            // Loop / defer / using bodies share the outer state — a
            // throw in the loop body uses the same in-state.
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                if try_body_throws_tainted_assignable_with_state(body, state, catch_types) {
                    return true;
                }
            }
            // Nested try: any throw in any of its three regions
            // (body / catch / finally) might be the catchable one.
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                if try_body_throws_tainted_assignable_with_state(body, state, catch_types) {
                    return true;
                }
                if try_body_throws_tainted_assignable_with_state(catch_events, state, catch_types) {
                    return true;
                }
                if try_body_throws_tainted_assignable_with_state(finally_events, state, catch_types) {
                    return true;
                }
            }
            _ => {}
        }
    }
    false
}

fn try_body_throws_tainted_with_state(events: &[FlowEvent], state: &mut TokenSet) -> bool {
    for event in events {
        match event {
            FlowEvent::Assign { .. } => {
                let cfg = InterTaintConfig {
                    sanitizers: TokenSet::default(),
                    budget: 0,
                    intra_worklist_cap: None,
                    ..Default::default()
                };
                apply_event_transfer(event, state, &cfg, None, None);
            }
            FlowEvent::Throw {
                value_name: Some(name),
                ..
            } => {
                if arg_text_is_tainted(name, state) {
                    return true;
                }
            }
            FlowEvent::Throw { value_name: None, .. } => {
                // Compound throw expression — adapter could not
                // resolve a bare identifier. Conservative: if any
                // taint is currently live, assume the throw could
                // carry it. This preserves recall on shapes like
                // `raise ValueError(tainted_payload)`.
                if !state.is_empty() {
                    return true;
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                let mut then_state = state.clone();
                if try_body_throws_tainted_with_state(then_events, &mut then_state) {
                    return true;
                }
                let mut else_state = state.clone();
                if try_body_throws_tainted_with_state(else_events, &mut else_state) {
                    return true;
                }
                state.extend(then_state);
                state.extend(else_state);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                if try_body_throws_tainted_with_state(body, state) {
                    return true;
                }
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                if try_body_throws_tainted_with_state(body, state)
                    || try_body_throws_tainted_with_state(catch_events, state)
                    || try_body_throws_tainted_with_state(finally_events, state)
                {
                    return true;
                }
            }
            _ => {}
        }
    }
    false
}

#[allow(clippy::too_many_arguments)] // stable parameter list — see calling site for shape
fn apply_return_taint(
    event: &FlowEvent,
    adjacent_source_call_args: &[EffectiveCallArg],
    target_destructure_index: Option<usize>,
    state: &mut TokenSet,
    config: &InterTaintConfig,
    db: &AnalyzerDb,
    aliases: &AHashMap<String, String>,
    alias_targets: &AHashMap<String, AliasTarget>,
    local_bindings: &AHashMap<String, FuncId>,
    caller: FuncId,
    summary_cache: &parking_lot::RwLock<AHashMap<FuncId, FunctionSummary>>,
    suppress_container_taint: bool,
) -> bool {
    let FlowEvent::Assign {
        target,
        source_call: Some(callee_name),
        source_call_args,
        source_names,
        span,
        ..
    } = event
    else {
        return false;
    };
    if target.is_empty() {
        return false;
    }
    if suppress_container_taint {
        return false;
    }
    if assignment_lhs_projects_collapsed_target(Some(db), *span, target) {
        return false;
    }
    let global = db.global_index();
    let mut tainted = false;
    let source_call_arg_values: Vec<EffectiveCallArg> = source_call_args
        .iter()
        .cloned()
        .map(EffectiveCallArg::positional)
        .collect();
    let effective_source_call_args = if !adjacent_source_call_args.is_empty() {
        adjacent_source_call_args
    } else {
        source_call_arg_values.as_slice()
    };
    let effective_source_call_arg_values: Vec<String> = effective_source_call_args
        .iter()
        .map(|arg| arg.value_text.clone())
        .collect();
    let resolve_scope = CallResolveScope {
        aliases,
        alias_targets,
        local_bindings,
        db,
        caller,
        config,
        // Summary-builder context doesn't share the propagation
        // cache today; populating it here would require threading
        // `resolved_calls` into every summary-pass entrypoint. Left
        // `None` so this path stays uncached.
        resolved_calls: None,
    };
    let mut candidates =
        resolve_call_candidates_with_caller_at(callee_name, &resolve_scope, &[], Some(*span));
    let constructor_candidates =
        constructor_candidates_for_class_call(db, caller, alias_targets, callee_name);
    if !constructor_candidates.is_empty() {
        candidates.retain(|candidate| {
            global
                .decl_of(SymbolId::new(candidate.func.raw()))
                .is_none_or(|decl| !matches!(decl.kind, DeclKind::Class | DeclKind::Struct))
        });
        for candidate in constructor_candidates {
            if !candidates.iter().any(|existing| existing.func == candidate.func) {
                candidates.push(candidate);
            }
        }
    }
    candidates = narrow_overload_candidates_by_arg_types(candidates, effective_source_call_args, db, caller);
    let tainted_call_arg = effective_source_call_args.iter().any(|arg| {
        effective_call_arg_is_tainted(arg, state) || effective_call_arg_has_descendant_taint(arg, state)
    });
    let has_named_field_args = source_call_args_have_named_fields(&effective_source_call_arg_values);
    let constructs_container = class_like_constructor_call(callee_name, db, caller, alias_targets)
        || (has_named_field_args && call_name_looks_type_constructor(callee_name))
        || candidates.iter().any(|candidate| {
            global
                .decl_of(SymbolId::new(candidate.func.raw()))
                .is_some_and(|decl| {
                    matches!(
                        decl.kind,
                        DeclKind::Class | DeclKind::Struct | DeclKind::Constructor
                    )
                })
        });
    let named_field_tainted = if constructs_container {
        apply_named_field_arg_taint(target, &effective_source_call_arg_values, state)
    } else {
        false
    };
    let source_call_rhs_tainted = source_call_rhs_is_tainted(
        callee_name,
        &effective_source_call_arg_values,
        source_names,
        state,
    );
    let source_names_tainted =
        assignment_source_names_any_tainted(source_names, *span, Some(db), Some(caller), state);
    let call_projection_tainted = source_names
        .iter()
        .any(|name| call_names_match(name, callee_name) && rhs_operand_is_tainted(name, state));
    if candidates.is_empty()
        && (unresolved_call_return_is_tainted(callee_name, state)
            || source_call_rhs_tainted
            || source_names_tainted
            || tainted_call_arg)
    {
        if named_field_tainted && has_named_field_args {
            return true;
        }
        if constructs_container && tainted_call_arg {
            return true;
        }
        insert_value_target_taint(state, target);
        if (source_names_tainted && rhs_has_descendant_shape(source_names))
            || (constructs_container && tainted_call_arg && !has_named_field_args)
        {
            insert_descendant_target_taint(state, target);
        }
        return true;
    }
    for candidate in &candidates {
        let summary = cache_or_insert_with(summary_cache, candidate.func, || {
            global
                .decl_of(SymbolId::new(candidate.func.raw()))
                .map(compute_function_summary)
                .unwrap_or_default()
        });
        let callee_decl = global.decl_of(SymbolId::new(candidate.func.raw()));
        let call_operand_tainted = source_names_tainted
            || source_call_rhs_tainted
            || effective_source_call_args
                .iter()
                .any(|arg| effective_call_arg_is_tainted(arg, state));
        let independent_rhs_operand_tainted = source_names_tainted
            && effective_source_call_arg_values.is_empty()
            && source_names
                .iter()
                .all(|name| !call_names_match(name, callee_name));
        let receiver_tainted = call_receiver_from_name(callee_name)
            .as_deref()
            .is_some_and(|receiver| receiver_expr_is_tainted(receiver, state));
        let implicit_receiver_return_tainted = callee_decl.is_some_and(|decl| {
            decl.receiver_param_index.is_none()
                && call_receiver_from_name(callee_name)
                    .as_deref()
                    .is_some_and(|receiver| implicit_receiver_return_is_tainted(decl, receiver, state))
        });
        let implicit_receiver_param_return_tainted = callee_decl.is_some_and(|decl| {
            decl.receiver_param_index.is_none()
                && matches!(decl.kind, DeclKind::Method)
                && summary.returns_taint_of.contains(&0)
                && call_receiver_from_name(callee_name)
                    .as_deref()
                    .is_some_and(|receiver| receiver_expr_is_tainted(receiver, state))
        });
        let constructor_field_tainted = callee_decl.is_some_and(|decl| {
            apply_constructor_receiver_field_taint(
                target,
                effective_source_call_args,
                decl,
                state,
                db,
                config,
            )
        });
        let constructor_has_receiver_field_writes =
            callee_decl.is_some_and(|decl| !decl.receiver_field_writes.is_empty());
        let value_tainted_transits = source_call_name_is_seeded(callee_name, state)
            || independent_rhs_operand_tainted
            || call_projection_tainted
            || implicit_receiver_return_tainted
            || implicit_receiver_param_return_tainted
            || (summary.returns_taint_of.is_empty()
                && !constructs_container
                && callee_decl.is_some_and(|decl| decl.flow_events.is_empty())
                && (call_operand_tainted || receiver_tainted))
            // The callee is a security-source-bearing function (a
            // source rule fires somewhere in its body). Closes the
            // cross-file recall regression where source-bearing
            // helpers silently dropped their return value (#95).
            // Engine never invents this set on its own — the
            // security layer populates it from matched source rules,
            // so empty-seed runs (the engine-level invariant) still
            // produce zero propagation records.
            || config.source_bearing_functions.contains(&candidate.func)
            || summary.returns_taint_of.iter().any(|&idx| {
                effective_arg_value_for_param(effective_source_call_args, callee_decl, idx)
                    .map(|arg_text| call_arg_is_directly_tainted(arg_text, state))
                    .unwrap_or(false)
                    || global
                        .decl_of(SymbolId::new(candidate.func.raw()))
                        .and_then(|decl| decl.receiver_param_index)
                        .is_some_and(|receiver_idx| {
                            receiver_idx == idx
                                && (source_names_tainted
                                    || call_receiver_from_name(callee_name)
                                            .as_deref()
                                            .is_some_and(|receiver| {
                                                call_arg_is_directly_tainted(receiver, state)
                                            }))
                        })
            })
            || higher_order_callback_return_taints_value(
                callee_decl,
                effective_source_call_args,
                &resolve_scope,
                summary_cache,
                state,
            );
        let access_path_tainted_transits = summary.returns_access_paths.iter().any(|returned| {
            effective_arg_value_for_param(effective_source_call_args, callee_decl, returned.param)
                .map(|arg_text| returned_access_path_is_tainted(arg_text, &returned.path, state))
                .unwrap_or(false)
                || global
                    .decl_of(SymbolId::new(candidate.func.raw()))
                    .and_then(|decl| decl.receiver_param_index)
                    .is_some_and(|receiver_idx| {
                        receiver_idx == returned.param
                            && call_receiver_from_name(callee_name)
                                .as_deref()
                                .is_some_and(|receiver| {
                                    returned_access_path_is_tainted(receiver, &returned.path, state)
                                })
                    })
        });
        let mut field_tainted_transits = false;
        for returned in &summary.returns_field_taint_of {
            let Some(arg_text) =
                effective_arg_value_for_param(effective_source_call_args, callee_decl, returned.param)
            else {
                continue;
            };
            let source_path_tainted = returned
                .source_path
                .as_deref()
                .is_some_and(|path| returned_access_path_is_tainted(arg_text, path, state));
            if !call_arg_is_directly_tainted(arg_text, state)
                && !returned_access_path_is_tainted(arg_text, &returned.field, state)
                && !source_path_tainted
            {
                continue;
            }
            let field_target = format!("{}.{}", normalise_target_text(target), returned.field);
            insert_value_target_taint(state, &field_target);
            field_tainted_transits = true;
        }
        let element_tainted_transits = target_destructure_index.is_some_and(|target_index| {
            summary.returns_element_taint_of.iter().any(|returned| {
                returned.index == target_index
                    && (effective_arg_value_for_param(
                        effective_source_call_args,
                        callee_decl,
                        returned.param,
                    )
                    .map(|arg_text| call_arg_is_directly_tainted(arg_text, state))
                    .unwrap_or(false)
                        || global
                            .decl_of(SymbolId::new(candidate.func.raw()))
                            .and_then(|decl| decl.receiver_param_index)
                            .is_some_and(|receiver_idx| {
                                receiver_idx == returned.param
                                    && call_receiver_from_name(callee_name)
                                        .as_deref()
                                        .is_some_and(|receiver| call_arg_is_directly_tainted(receiver, state))
                            }))
            })
        });
        let descendant_tainted_transits = summary.returns_descendant_taint_of.iter().any(|&idx| {
            effective_arg_value_for_param(effective_source_call_args, callee_decl, idx)
                .map(|arg_text| actual_has_descendant_taint(arg_text, state))
                .unwrap_or(false)
                || global
                    .decl_of(SymbolId::new(candidate.func.raw()))
                    .and_then(|decl| decl.receiver_param_index)
                    .is_some_and(|receiver_idx| {
                        receiver_idx == idx
                            && call_receiver_from_name(callee_name)
                                .as_deref()
                                .is_some_and(|receiver| actual_has_descendant_taint(receiver, state))
                    })
        });
        let container_tainted_transits = target_destructure_index.is_none()
            && summary.returns_container_taint_of.iter().any(|&idx| {
                effective_arg_value_for_param(effective_source_call_args, callee_decl, idx)
                    .map(|arg_text| call_arg_is_directly_tainted(arg_text, state))
                    .unwrap_or(false)
                    || global
                        .decl_of(SymbolId::new(candidate.func.raw()))
                        .and_then(|decl| decl.receiver_param_index)
                        .is_some_and(|receiver_idx| {
                            receiver_idx == idx
                                && call_receiver_from_name(callee_name)
                                    .as_deref()
                                    .is_some_and(|receiver| call_arg_is_directly_tainted(receiver, state))
                        })
            });
        if value_tainted_transits {
            insert_value_target_taint(state, target);
            tainted = true;
        }
        if access_path_tainted_transits {
            insert_value_target_taint(state, target);
            tainted = true;
        }
        if element_tainted_transits {
            insert_value_target_taint(state, target);
            tainted = true;
        }
        if descendant_tainted_transits || container_tainted_transits {
            insert_descendant_target_taint(state, target);
            tainted = true;
        }
        if (named_field_tainted && has_named_field_args)
            || constructor_field_tainted
            || field_tainted_transits
        {
            tainted = true;
        } else if constructs_container && tainted_call_arg && !constructor_has_receiver_field_writes {
            insert_descendant_target_taint(state, target);
            tainted = true;
        }
        if descendant_tainted_transits {
            insert_value_target_taint(state, target);
            tainted = true;
        }
    }
    if !tainted && !candidates.is_empty() {
        state.remove(target);
    }
    tainted
}

fn higher_order_callback_return_taints_value(
    callee_decl: Option<&Decl>,
    effective_source_call_args: &[EffectiveCallArg],
    resolve_scope: &CallResolveScope<'_>,
    summary_cache: &parking_lot::RwLock<AHashMap<FuncId, FunctionSummary>>,
    state: &TokenSet,
) -> bool {
    let Some(callee_decl) = callee_decl else {
        return false;
    };
    let Some(FlowEvent::Call { name, args, .. }) = terminal_callback_call_event(&callee_decl.flow_events)
    else {
        return false;
    };
    let Some(callback_param_idx) = callee_decl
        .params
        .iter()
        .position(|param| call_names_match(param, name) || same_identifier_name(param, name))
    else {
        return false;
    };
    let Some(callback_actual) =
        effective_arg_for_param(effective_source_call_args, Some(callee_decl), callback_param_idx)
    else {
        return false;
    };
    let callback_name = callback_actual.value_text.trim();
    if callback_name.is_empty() || is_quoted_literal(callback_name) {
        return false;
    }
    let callback_candidates = resolve_call_candidates_with_caller_at(callback_name, resolve_scope, &[], None);
    if callback_candidates.is_empty() {
        return false;
    }
    let callback_call_args: Vec<EffectiveCallArg> =
        args.iter().map(EffectiveCallArg::from_call_arg).collect();
    let global = resolve_scope.db.global_index();
    callback_candidates.iter().any(|candidate| {
        let callback_decl = global.decl_of(SymbolId::new(candidate.func.raw()));
        let callback_summary = cache_or_insert_with(summary_cache, candidate.func, || {
            callback_decl.map(compute_function_summary).unwrap_or_default()
        });
        callback_summary.returns_taint_of.iter().any(|&returned_idx| {
            callback_returned_param_maps_to_tainted_actual(
                &callback_call_args,
                callback_decl,
                returned_idx,
                callee_decl,
                effective_source_call_args,
                state,
                false,
            )
        }) || callback_summary
            .returns_descendant_taint_of
            .iter()
            .any(|&returned_idx| {
                callback_returned_param_maps_to_tainted_actual(
                    &callback_call_args,
                    callback_decl,
                    returned_idx,
                    callee_decl,
                    effective_source_call_args,
                    state,
                    true,
                )
            })
    })
}

fn terminal_callback_call_event(events: &[FlowEvent]) -> Option<&FlowEvent> {
    match events.last()? {
        call @ FlowEvent::Call { .. } => Some(call),
        FlowEvent::Branch {
            then_events,
            else_events,
            ..
        } => terminal_callback_call_event(then_events).or_else(|| terminal_callback_call_event(else_events)),
        FlowEvent::Try {
            body,
            catch_events,
            finally_events,
            ..
        } => terminal_callback_call_event(body)
            .or_else(|| terminal_callback_call_event(catch_events))
            .or_else(|| terminal_callback_call_event(finally_events)),
        FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => terminal_callback_call_event(body),
        _ => None,
    }
}

fn callback_returned_param_maps_to_tainted_actual(
    callback_call_args: &[EffectiveCallArg],
    callback_decl: Option<&Decl>,
    returned_idx: usize,
    wrapper_decl: &Decl,
    wrapper_actual_args: &[EffectiveCallArg],
    state: &TokenSet,
    descendant: bool,
) -> bool {
    let Some(wrapper_arg_text) =
        effective_arg_value_for_param(callback_call_args, callback_decl, returned_idx)
    else {
        return false;
    };
    let Some(wrapper_param_idx) = wrapper_decl.params.iter().position(|param| {
        call_names_match(param, wrapper_arg_text) || same_identifier_name(param, wrapper_arg_text)
    }) else {
        return false;
    };
    let Some(actual) = effective_arg_for_param(wrapper_actual_args, Some(wrapper_decl), wrapper_param_idx)
    else {
        return false;
    };
    if descendant {
        effective_call_arg_has_descendant_taint(actual, state)
    } else {
        effective_call_arg_has_direct_value_taint(actual, state)
    }
}

fn source_call_args_have_named_fields(args: &[String]) -> bool {
    args.iter().any(|arg| !named_field_initializers(arg).is_empty())
}

fn effective_arg_for_param<'a>(
    args: &'a [EffectiveCallArg],
    decl: Option<&Decl>,
    param_idx: usize,
) -> Option<&'a EffectiveCallArg> {
    let Some(decl) = decl else {
        return args.get(param_idx);
    };
    if let Some(param_name) = decl.params.get(param_idx).map(|param| param.trim()) {
        if !param_name.is_empty() {
            if let Some(named) = args
                .iter()
                .find(|arg| arg.name.as_deref().is_some_and(|name| name.trim() == param_name))
            {
                return Some(named);
            }
        }
    }
    if decl
        .receiver_param_index
        .is_some_and(|receiver_idx| receiver_idx == param_idx)
    {
        return None;
    }
    let positional_idx = decl
        .receiver_param_index
        .filter(|receiver_idx| *receiver_idx < param_idx)
        .map_or(param_idx, |_| param_idx.saturating_sub(1));
    args.iter().filter(|arg| arg.name.is_none()).nth(positional_idx)
}

fn effective_arg_value_for_param<'a>(
    args: &'a [EffectiveCallArg],
    decl: Option<&Decl>,
    param_idx: usize,
) -> Option<&'a str> {
    effective_arg_for_param(args, decl, param_idx).map(|arg| arg.value_text.as_str())
}

fn narrow_overload_candidates_by_arg_types(
    candidates: Vec<ResolvedCallee>,
    args: &[EffectiveCallArg],
    db: &AnalyzerDb,
    caller: FuncId,
) -> Vec<ResolvedCallee> {
    if candidates.len() <= 1 || args.is_empty() {
        return candidates;
    }
    let funcs = candidates
        .iter()
        .map(|candidate| candidate.func)
        .collect::<Vec<_>>();
    if !candidates_form_semantic_overload_family(db, &funcs) {
        return candidates;
    }
    let global = db.global_index();
    let Some(caller_decl) = global.decl_of(SymbolId::new(caller.raw())) else {
        return candidates;
    };
    let narrowed = candidates
        .iter()
        .filter(|candidate| {
            let Some(callee_decl) = global.decl_of(SymbolId::new(candidate.func.raw())) else {
                return false;
            };
            candidate_matches_typed_args(caller_decl, callee_decl, args).unwrap_or(false)
        })
        .cloned()
        .collect::<Vec<_>>();
    if narrowed.is_empty() || narrowed.len() == candidates.len() {
        candidates
    } else {
        narrowed
    }
}

fn candidate_matches_typed_args(
    caller_decl: &Decl,
    callee_decl: &Decl,
    args: &[EffectiveCallArg],
) -> Option<bool> {
    let mut checked = false;
    for (param_idx, param_name) in callee_decl.params.iter().enumerate() {
        let Some(expected_type) = type_alias_name_for_param(callee_decl, param_name) else {
            continue;
        };
        let Some(arg_text) = effective_arg_value_for_param(args, Some(callee_decl), param_idx) else {
            continue;
        };
        let Some(actual_type) = actual_arg_type_name(caller_decl, arg_text) else {
            continue;
        };
        checked = true;
        if !type_names_compatible(&actual_type, expected_type) {
            return Some(false);
        }
    }
    checked.then_some(true)
}

fn type_alias_name_for_param<'a>(decl: &'a Decl, param_name: &str) -> Option<&'a str> {
    let param_name = param_name.trim();
    if param_name.is_empty() {
        return None;
    }
    decl.type_aliases
        .iter()
        .find(|alias| alias.name == param_name)
        .map(|alias| alias.type_name.as_str())
}

fn actual_arg_type_name(caller_decl: &Decl, arg_text: &str) -> Option<String> {
    let arg_text = arg_text.trim();
    if arg_text.is_empty() {
        return None;
    }
    if is_quoted_literal(arg_text) {
        return Some("String".to_string());
    }
    let lowered = arg_text.to_ascii_lowercase();
    if matches!(lowered.as_str(), "true" | "false") {
        return Some("Bool".to_string());
    }
    if arg_text.parse::<i64>().is_ok() {
        return Some("Int".to_string());
    }
    if arg_text.parse::<f64>().is_ok() && arg_text.contains('.') {
        return Some("Double".to_string());
    }
    type_alias_for_receiver(caller_decl, arg_text)
}

fn type_names_compatible(actual: &str, expected: &str) -> bool {
    canonical_overload_type_name(actual) == canonical_overload_type_name(expected)
}

fn canonical_overload_type_name(type_name: &str) -> String {
    type_name
        .trim()
        .trim_matches('&')
        .trim_matches('*')
        .trim_end_matches('?')
        .trim_end_matches('!')
        .rsplit(&['.', ':'][..])
        .next()
        .unwrap_or(type_name)
        .trim()
        .to_ascii_lowercase()
}

fn apply_constructor_receiver_field_taint(
    target: &str,
    args: &[EffectiveCallArg],
    decl: &Decl,
    state: &mut TokenSet,
    db: &AnalyzerDb,
    config: &InterTaintConfig,
) -> bool {
    let writes = constructor_receiver_field_writes_for_decl(decl, db, config);
    if writes.is_empty() {
        return false;
    }
    let target = normalise_target_text(target);
    if target.is_empty() {
        return false;
    }
    let receiver_names = constructor_receiver_names_for_decl(decl);
    if receiver_names.is_empty() {
        return false;
    }
    let mut changed = false;
    for write in &writes {
        let Some(field_tail) = receiver_names
            .iter()
            .find_map(|receiver_name| receiver_field_write_tail(&write.target, receiver_name))
        else {
            continue;
        };
        let field_target = format!("{target}.{field_tail}");
        for source_param in &write.source_param_indices {
            let Some(arg) = effective_arg_for_param(args, Some(decl), *source_param) else {
                continue;
            };
            if effective_call_arg_has_direct_value_taint(arg, state) {
                let before = state.len();
                insert_value_target_taint(state, &field_target);
                changed |= state.len() != before;
            }
            changed |= copy_descendant_taint_to_target(state, &field_target, &arg.value_text);
            for source_name in &arg.source_names {
                changed |= copy_descendant_taint_to_target(state, &field_target, source_name);
            }
        }
    }
    changed
}

fn constructor_receiver_names_for_decl(decl: &Decl) -> Vec<String> {
    if let Some(receiver_idx) = decl.receiver_param_index {
        return decl
            .params
            .get(receiver_idx)
            .map(|receiver| vec![receiver.clone()])
            .unwrap_or_default();
    }
    let mut names = decl.implicit_receiver_names.clone();
    for write in &decl.receiver_field_writes {
        let target = normalise_target_text(&write.target);
        let Some((base, _)) = target.split_once('.') else {
            continue;
        };
        if !base.trim().is_empty() && !names.iter().any(|existing| existing == base) {
            names.push(base.to_string());
        }
    }
    names
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ConstructorReceiverFieldWrite {
    target: String,
    source_param_indices: Vec<usize>,
}

fn constructor_receiver_field_writes_for_decl(
    decl: &Decl,
    db: &AnalyzerDb,
    config: &InterTaintConfig,
) -> Vec<ConstructorReceiverFieldWrite> {
    let mut seen = AHashSet::new();
    collect_constructor_receiver_field_writes(decl, db, config, &mut seen, 0)
}

fn collect_constructor_receiver_field_writes(
    decl: &Decl,
    db: &AnalyzerDb,
    config: &InterTaintConfig,
    seen: &mut AHashSet<FuncId>,
    depth: usize,
) -> Vec<ConstructorReceiverFieldWrite> {
    let func = FuncId::new(decl.symbol.raw());
    if depth > 8 || !seen.insert(func) {
        return Vec::new();
    }

    let mut out = decl
        .receiver_field_writes
        .iter()
        .map(|write| ConstructorReceiverFieldWrite {
            target: write.target.clone(),
            source_param_indices: write.source_param_indices.clone(),
        })
        .collect::<Vec<_>>();

    collect_super_constructor_receiver_field_writes(
        &decl.flow_events,
        decl,
        db,
        config,
        seen,
        depth,
        &mut out,
    );
    dedup_constructor_receiver_field_writes(&mut out);
    out
}

fn collect_super_constructor_receiver_field_writes(
    events: &[FlowEvent],
    decl: &Decl,
    db: &AnalyzerDb,
    config: &InterTaintConfig,
    seen: &mut AHashSet<FuncId>,
    depth: usize,
    out: &mut Vec<ConstructorReceiverFieldWrite>,
) {
    for event in events {
        match event {
            FlowEvent::Call {
                name,
                receiver,
                args,
                span,
                ..
            } => {
                collect_super_constructor_call_receiver_field_writes(
                    name,
                    receiver.as_deref(),
                    args,
                    *span,
                    decl,
                    db,
                    config,
                    seen,
                    depth,
                    out,
                );
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                collect_super_constructor_receiver_field_writes(
                    then_events,
                    decl,
                    db,
                    config,
                    seen,
                    depth,
                    out,
                );
                collect_super_constructor_receiver_field_writes(
                    else_events,
                    decl,
                    db,
                    config,
                    seen,
                    depth,
                    out,
                );
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                collect_super_constructor_receiver_field_writes(body, decl, db, config, seen, depth, out);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                collect_super_constructor_receiver_field_writes(body, decl, db, config, seen, depth, out);
                collect_super_constructor_receiver_field_writes(
                    catch_events,
                    decl,
                    db,
                    config,
                    seen,
                    depth,
                    out,
                );
                collect_super_constructor_receiver_field_writes(
                    finally_events,
                    decl,
                    db,
                    config,
                    seen,
                    depth,
                    out,
                );
            }
            _ => {}
        }
    }
}

#[allow(clippy::too_many_arguments)] // mirrors the FlowEvent::Call shape and keeps recursion local
fn collect_super_constructor_call_receiver_field_writes(
    name: &str,
    receiver: Option<&str>,
    args: &[CallArg],
    span: Span,
    decl: &Decl,
    db: &AnalyzerDb,
    config: &InterTaintConfig,
    seen: &mut AHashSet<FuncId>,
    depth: usize,
    out: &mut Vec<ConstructorReceiverFieldWrite>,
) {
    let Some(receiver) = receiver else {
        return;
    };
    if !is_super_receiver_for_decl(db, decl, receiver) {
        return;
    }
    let Some(current_receiver_idx) = decl.receiver_param_index else {
        return;
    };
    let Some(current_receiver_name) = decl.params.get(current_receiver_idx).map(String::as_str) else {
        return;
    };
    let Some((aliases, alias_targets, local_bindings)) = resolve_context_for_decl(db, decl) else {
        return;
    };
    let scope = CallResolveScope {
        aliases: &aliases,
        alias_targets: &alias_targets,
        local_bindings: &local_bindings,
        db,
        caller: FuncId::new(decl.symbol.raw()),
        config,
        resolved_calls: None,
    };
    let candidates = resolve_call_candidates_with_caller_at(name, &scope, &[], Some(span));
    if candidates.is_empty() {
        return;
    }
    let effective_args = args
        .iter()
        .map(EffectiveCallArg::from_call_arg)
        .collect::<Vec<_>>();
    let global = db.global_index();
    for candidate in candidates {
        let Some(callee_decl) = global.decl_of(SymbolId::new(candidate.func.raw())) else {
            continue;
        };
        if !matches!(callee_decl.kind, DeclKind::Constructor | DeclKind::Method) {
            continue;
        }
        let Some(callee_receiver_idx) = callee_decl.receiver_param_index else {
            continue;
        };
        let Some(callee_receiver_name) = callee_decl.params.get(callee_receiver_idx).map(String::as_str)
        else {
            continue;
        };
        let callee_writes =
            collect_constructor_receiver_field_writes(callee_decl, db, config, seen, depth + 1);
        for write in callee_writes {
            let Some(field_tail) = receiver_field_write_tail(&write.target, callee_receiver_name) else {
                continue;
            };
            let mut mapped_sources = Vec::new();
            for source_param in write.source_param_indices {
                let Some(arg_text) =
                    effective_arg_value_for_param(&effective_args, Some(callee_decl), source_param)
                else {
                    continue;
                };
                if let Some(current_param) = param_index_for_exact_arg_value(decl, arg_text) {
                    if !mapped_sources.contains(&current_param) {
                        mapped_sources.push(current_param);
                    }
                }
            }
            if mapped_sources.is_empty() {
                continue;
            }
            out.push(ConstructorReceiverFieldWrite {
                target: format!("{current_receiver_name}.{field_tail}"),
                source_param_indices: mapped_sources,
            });
        }
    }
}

type DeclResolveContext = (
    AHashMap<String, String>,
    AHashMap<String, AliasTarget>,
    AHashMap<String, FuncId>,
);

fn resolve_context_for_decl(db: &AnalyzerDb, decl: &Decl) -> Option<DeclResolveContext> {
    let global = db.global_index();
    let file = global.declaring_file(decl.symbol)?;
    let imports = db.imports_for(file);
    let aliases = alias_map_for_file(&imports);
    let alias_targets = alias_targets_for_decl(&imports, decl);
    let local_bindings = bonsai_callgraph::collect_local_callable_bindings_with_aliases(
        &decl.flow_events,
        &global,
        decl,
        &alias_targets,
    );
    Some((aliases, alias_targets, local_bindings))
}

fn param_index_for_exact_arg_value(decl: &Decl, value: &str) -> Option<usize> {
    let value = normalise_target_text(value);
    if value.is_empty() || text_looks_qualified(&value) {
        return None;
    }
    decl.params
        .iter()
        .position(|param| normalise_target_text(param) == value)
}

fn dedup_constructor_receiver_field_writes(writes: &mut Vec<ConstructorReceiverFieldWrite>) {
    for write in writes.iter_mut() {
        write.source_param_indices.sort_unstable();
        write.source_param_indices.dedup();
    }
    writes.sort_by(|a, b| {
        a.target
            .cmp(&b.target)
            .then(a.source_param_indices.cmp(&b.source_param_indices))
    });
    writes.dedup();
}

fn receiver_field_write_tail(target: &str, receiver_name: &str) -> Option<String> {
    let target = normalise_target_text(target);
    let receiver = normalise_target_text(receiver_name);
    if target.is_empty() || receiver.is_empty() {
        return None;
    }
    target
        .strip_prefix(receiver.as_str())
        .and_then(|tail| tail.strip_prefix('.'))
        .filter(|tail| !tail.trim().is_empty())
        .map(ToString::to_string)
}

fn copy_descendant_taint_to_target(state: &mut TokenSet, target: &str, actual_text: &str) -> bool {
    let target = normalise_target_text(target);
    let actual = normalise_target_text(actual_text);
    if target.is_empty() || actual.is_empty() {
        return false;
    }
    let mut changed = false;
    for actual_key in access_alias_keys(&actual) {
        let wildcard = format!("{actual_key}.*");
        for seed in state.clone() {
            let seed = normalise_qualified_text(&seed);
            if seed == wildcard {
                changed |= state.insert(format!("{target}.*"));
                continue;
            }
            let Some(tail) = seed.strip_prefix(actual_key.as_str()) else {
                continue;
            };
            if !tail.starts_with('.') {
                continue;
            }
            changed |= state.insert(format!("{target}{tail}"));
        }
    }
    changed
}

fn copy_assignment_descendant_taint(state: &mut TokenSet, target: &str, actual_text: &str) -> bool {
    if text_looks_qualified(&normalise_target_text(target)) {
        copy_descendant_taint_to_target(state, target, actual_text)
    } else {
        copy_mapped_descendant_taint(state, target, actual_text)
    }
}

fn returned_access_path_is_tainted(actual_text: &str, path: &str, state: &TokenSet) -> bool {
    let actual = normalise_target_text(actual_text);
    let path = path.trim().trim_matches('.');
    if actual.is_empty() || path.is_empty() {
        return false;
    }
    let qualified = format!("{actual}.{path}");
    arg_text_is_tainted(&qualified, state)
        || actual_has_descendant_taint(actual_text, state)
        || actual_has_value_taint(actual_text, state)
        || state.contains(actual_text.trim())
        || state.contains(&actual)
}

fn call_name_looks_type_constructor(name: &str) -> bool {
    let tail = short_tail(name.trim());
    tail.chars()
        .next()
        .is_some_and(|ch| ch == '_' || ch.is_ascii_uppercase())
}

fn apply_named_field_arg_taint(target: &str, args: &[String], state: &mut TokenSet) -> bool {
    let mut changed = false;
    for arg in args {
        for (field, value) in named_field_initializers(arg) {
            if arg_text_is_tainted(&value, state) || actual_has_descendant_taint(&value, state) {
                let field_target = format!("{}.{}", normalise_target_text(target), field);
                insert_value_target_taint(state, &field_target);
                if actual_has_descendant_taint(&value, state) {
                    insert_descendant_target_taint(state, &field_target);
                }
                changed = true;
            }
        }
    }
    changed
}

fn named_field_update_copies_tainted_base(
    source_names: &[String],
    field_updates: &[(String, String)],
    span: Span,
    db: Option<&AnalyzerDb>,
    caller: Option<FuncId>,
    state: &TokenSet,
) -> bool {
    let qualified_bases = synthetic_qualified_source_bases(source_names, span, db);
    source_names.iter().any(|source| {
        let canonical = canonical_bare_name(source);
        if canonical.is_empty() || named_field_update_mentions_source(field_updates, &canonical) {
            return false;
        }
        assignment_source_name_is_value_tainted(source, &qualified_bases, db, caller, state)
            || actual_has_descendant_taint(source, state)
            || arg_text_has_mapped_descendant_taint(source, state)
    })
}

fn named_field_update_mentions_source(field_updates: &[(String, String)], source: &str) -> bool {
    field_updates.iter().any(|(field, value)| {
        canonical_bare_name(field) == source || expression_mentions_source(value, source)
    })
}

fn expression_mentions_source(value: &str, source: &str) -> bool {
    let value_norm = normalise_target_text(value);
    let source_norm = normalise_target_text(source);
    if source_norm.is_empty() {
        return false;
    }
    value_norm == source_norm
        || value_norm
            .strip_prefix(&source_norm)
            .is_some_and(|tail| tail.starts_with('.') || tail.starts_with('['))
        || identifier_value_occurs(value, source)
}

fn named_field_initializers(text: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let trimmed = text.trim();
    let (body, allow_shorthand) = if let Some(body) = strip_prefixed_brace_literal_outer(trimmed) {
        (body, true)
    } else if let Some(body) = strip_balanced_outer(trimmed, '{', '}') {
        (body, true)
    } else if let Some(body) = struct_literal_body(trimmed) {
        (body, true)
    } else if let Some(body) = type_constructor_arg_body(trimmed) {
        (body, false)
    } else if let Some(body) = strip_balanced_outer(trimmed, '(', ')') {
        (body, false)
    } else {
        (trimmed, false)
    };
    for part in split_top_level(body, ',') {
        if let Some((field, value)) = split_named_field_initializer(&part) {
            out.push((field, value));
        } else if allow_shorthand {
            if let Some(field) = shorthand_field_initializer(&part) {
                out.push((field, part.trim().to_string()));
            }
        }
    }
    out
}

fn named_field_initializer_values_for_target(target: &str, rhs: &str) -> Vec<String> {
    let target = normalise_target_text(target);
    if target.is_empty() || !text_looks_qualified(&target) {
        return Vec::new();
    }
    let Some(field) = target.rsplit('.').next().map(str::trim) else {
        return Vec::new();
    };
    if field.is_empty() {
        return Vec::new();
    }
    let mut values = Vec::new();
    collect_named_field_initializer_values_for_field(rhs, field, &mut values);
    values
}

fn collect_named_field_initializer_values_for_field(text: &str, field: &str, out: &mut Vec<String>) {
    for (candidate, value) in named_field_initializers(text) {
        if candidate == field && !out.iter().any(|existing| existing == &value) {
            out.push(value);
        }
    }
    for literal in top_level_brace_literals(text) {
        for (candidate, value) in named_field_initializers(&literal) {
            if candidate == field && !out.iter().any(|existing| existing == &value) {
                out.push(value);
            }
        }
    }
}

fn top_level_brace_literals(text: &str) -> Vec<String> {
    let mut literals = Vec::new();
    let stripped = strip_redundant_outer_parens(text.trim());
    collect_top_level_brace_literals(stripped, &mut literals);
    literals
}

fn strip_redundant_outer_parens(mut text: &str) -> &str {
    loop {
        let Some(inner) = strip_balanced_outer(text.trim(), '(', ')') else {
            return text.trim();
        };
        text = inner;
    }
}

fn collect_top_level_brace_literals(text: &str, out: &mut Vec<String>) {
    let mut quote: Option<char> = None;
    let mut escaped = false;
    let mut depth = 0usize;
    let mut literal_start: Option<usize> = None;
    for (idx, ch) in text.char_indices() {
        if let Some(q) = quote {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == q {
                quote = None;
            }
            continue;
        }
        if matches!(ch, '\'' | '"' | '`') {
            quote = Some(ch);
            continue;
        }
        match ch {
            '{' => {
                if depth == 0 {
                    literal_start = Some(idx);
                }
                depth = depth.saturating_add(1);
            }
            '}' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    if let Some(start) = literal_start.take() {
                        out.push(text[start..idx + ch.len_utf8()].to_string());
                    }
                }
            }
            _ => {}
        }
    }
}

fn struct_literal_body(text: &str) -> Option<&str> {
    let open = text.find('{')?;
    if !text.ends_with('}') {
        return None;
    }
    let prefix = text[..open].trim();
    if prefix.contains("->") {
        return None;
    }
    if prefix.is_empty()
        || !prefix
            .chars()
            .any(|ch| ch == '_' || ch == ':' || ch.is_ascii_alphabetic())
    {
        return None;
    }
    strip_balanced_outer(text[open..].trim(), '{', '}')
}

fn type_constructor_arg_body(text: &str) -> Option<&str> {
    let mut text = text.trim();
    for keyword in ["return ", "yield ", "new ", "const "] {
        if let Some(rest) = text.strip_prefix(keyword) {
            text = rest.trim_start();
        }
    }
    let open = text.find('(')?;
    let candidate = text[..open].trim();
    if !type_constructor_prefix_looks_like_type(candidate) {
        return None;
    }
    strip_balanced_outer(text[open..].trim(), '(', ')')
}

fn type_constructor_prefix_looks_like_type(candidate: &str) -> bool {
    let candidate = candidate.trim();
    if candidate.is_empty() || candidate.contains(char::is_whitespace) {
        return false;
    }
    candidate
        .split("::")
        .flat_map(|part| part.split('.'))
        .map(|part| part.split('<').next().unwrap_or(part).trim())
        .any(|part| {
            part == "Self"
                || part
                    .chars()
                    .next()
                    .is_some_and(|ch| ch == '_' || ch.is_ascii_uppercase())
        })
}

fn shorthand_field_initializer(part: &str) -> Option<String> {
    let part = part.trim();
    if part.is_empty() || part.contains([':', '=', '(', ')', '[', ']']) {
        return None;
    }
    field_name_from_initializer_lhs(part)
}

fn split_named_field_initializer(part: &str) -> Option<(String, String)> {
    let (idx, separator_len) = find_top_level_field_separator(part)?;
    let field = field_name_from_initializer_lhs(part[..idx].trim())?;
    let value = part[idx + separator_len..].trim();
    if value.is_empty() {
        return None;
    }
    Some((field, value.to_string()))
}

fn find_top_level_field_separator(text: &str) -> Option<(usize, usize)> {
    let mut quote: Option<char> = None;
    let mut escaped = false;
    let mut depth = 0usize;
    let mut iter = text.char_indices().peekable();
    while let Some((idx, ch)) = iter.next() {
        if let Some(q) = quote {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == q {
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
            ':' if depth == 0 => {
                if text[idx..].starts_with("::") || text[idx..].starts_with(":=") {
                    continue;
                }
                return Some((idx, 1));
            }
            '=' if depth == 0 => {
                let prev = text[..idx].chars().next_back();
                let next = iter.peek().map(|(_, next)| *next);
                if matches!(next, Some('>')) {
                    return Some((idx, 2));
                }
                if matches!(prev, Some('=' | '!' | '<' | '>' | ':')) || matches!(next, Some('=')) {
                    continue;
                }
                return Some((idx, 1));
            }
            _ => {}
        }
    }
    None
}

fn field_name_from_initializer_lhs(lhs: &str) -> Option<String> {
    let lhs = lhs
        .trim()
        .trim_start_matches('.')
        .trim_matches(|ch| matches!(ch, '"' | '\'' | '`'));
    if lhs.is_empty() {
        return None;
    }
    let normalised = normalise_qualified_text(lhs);
    let candidate = normalised
        .rsplit('.')
        .next()
        .unwrap_or(normalised.as_str())
        .trim();
    if candidate.is_empty()
        || candidate
            .chars()
            .next()
            .is_some_and(|ch| !(ch == '_' || ch.is_ascii_alphabetic()))
        || !candidate
            .chars()
            .all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
    {
        return None;
    }
    Some(candidate.to_string())
}

fn strip_prefixed_brace_literal_outer(text: &str) -> Option<&str> {
    text.strip_prefix("#{")
        .or_else(|| text.strip_prefix("%{"))?
        .strip_suffix('}')
}

fn strip_balanced_outer(text: &str, open: char, close: char) -> Option<&str> {
    if !text.starts_with(open) || !text.ends_with(close) {
        return None;
    }
    let mut quote: Option<char> = None;
    let mut escaped = false;
    let mut depth = 0isize;
    for (idx, ch) in text.char_indices() {
        if let Some(q) = quote {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == q {
                quote = None;
            }
            continue;
        }
        if matches!(ch, '\'' | '"' | '`') {
            quote = Some(ch);
            continue;
        }
        if ch == open {
            depth += 1;
        } else if ch == close {
            depth -= 1;
            if depth == 0 && idx + ch.len_utf8() != text.len() {
                return None;
            }
        }
        if depth < 0 {
            return None;
        }
    }
    (depth == 0).then_some(&text[open.len_utf8()..text.len() - close.len_utf8()])
}

fn split_top_level(text: &str, delimiter: char) -> Vec<String> {
    let mut out = Vec::new();
    let mut quote: Option<char> = None;
    let mut escaped = false;
    let mut depth = 0usize;
    let mut start = 0usize;
    for (idx, ch) in text.char_indices() {
        if let Some(q) = quote {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == q {
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
            ch if ch == delimiter && depth == 0 => {
                let part = text[start..idx].trim();
                if !part.is_empty() {
                    out.push(part.to_string());
                }
                start = idx + ch.len_utf8();
            }
            _ => {}
        }
    }
    let part = text[start..].trim();
    if !part.is_empty() {
        out.push(part.to_string());
    }
    out
}

fn class_like_constructor_call(
    callee_name: &str,
    db: &AnalyzerDb,
    caller: FuncId,
    alias_targets: &AHashMap<String, AliasTarget>,
) -> bool {
    let global = db.global_index();
    let Some(caller_decl) = global.decl_of(SymbolId::new(caller.raw())) else {
        return false;
    };
    let path_lookup = |file| {
        db.vfs()
            .path(file)
            .ok()
            .map(|path| path.to_string_lossy().into_owned())
    };
    let ctx = ResolveContext::new(caller_decl.span.file, &caller_decl.module_path)
        .with_alias_map(alias_targets)
        .with_file_path_lookup(&path_lookup);
    if !resolve_class(&global, callee_name, &ctx).is_empty() {
        return true;
    }
    let tail = short_tail(callee_name);
    tail != callee_name && !resolve_class(&global, tail, &ctx).is_empty()
}

fn constructor_candidates_for_class_call(
    db: &AnalyzerDb,
    caller: FuncId,
    alias_targets: &AHashMap<String, AliasTarget>,
    callee_name: &str,
) -> Vec<ResolvedCallee> {
    let global = db.global_index();
    let Some(caller_decl) = global.decl_of(SymbolId::new(caller.raw())) else {
        return Vec::new();
    };
    let path_lookup = |file| {
        db.vfs()
            .path(file)
            .ok()
            .map(|path| path.to_string_lossy().into_owned())
    };
    let ctx = ResolveContext::new(caller_decl.span.file, &caller_decl.module_path)
        .with_alias_map(alias_targets)
        .with_file_path_lookup(&path_lookup);
    let mut class_symbols = Vec::new();
    for lookup in constructor_class_lookup_names(callee_name, db, caller) {
        for class_sym in resolve_class(&global, &lookup, &ctx) {
            if !class_symbols.contains(&class_sym) {
                class_symbols.push(class_sym);
            }
        }
    }
    let mut funcs = Vec::new();
    for class_sym in class_symbols {
        let Some(class_decl) = global.decl_of(class_sym) else {
            continue;
        };
        let mut seen = AHashSet::new();
        for method_name in constructor_method_names_for_class(db, caller, class_decl.name.as_str()) {
            collect_method_candidates_for_class(
                &global,
                class_sym,
                &method_name,
                &ctx,
                &mut seen,
                &mut funcs,
            );
        }
    }
    let kind = if funcs.len() <= 1 {
        EdgeKind::Direct
    } else {
        EdgeKind::Virtual
    };
    funcs
        .into_iter()
        .map(|func| ResolvedCallee {
            func,
            kind,
            precision: Precision::Narrowed,
        })
        .collect()
}

fn constructor_class_lookup_names(callee_name: &str, db: &AnalyzerDb, caller: FuncId) -> Vec<String> {
    let mut out = Vec::new();
    let mut push = |name: &str| {
        let name = name.trim();
        if !name.is_empty() && !out.iter().any(|existing| existing == name) {
            out.push(name.to_string());
        }
    };
    push(callee_name);
    let tail = short_tail(callee_name);
    if tail != callee_name {
        push(tail);
    }
    if configured_constructor_method_for_caller(db, caller, tail) {
        if let Some(receiver) = call_receiver_from_name(callee_name) {
            push(&receiver);
        }
    }
    out
}

fn configured_constructor_method_for_caller(db: &AnalyzerDb, caller: FuncId, method_name: &str) -> bool {
    let Some(caller_file) = db.global_index().declaring_file(SymbolId::new(caller.raw())) else {
        return false;
    };
    db.adapter_for(caller_file)
        .map(|adapter| {
            adapter
                .capabilities()
                .effective_constructor_method_names()
                .contains(&method_name)
        })
        .unwrap_or_else(|| bonsai_common::CONSTRUCTOR_METHOD_NAMES.contains(&method_name))
}

fn super_receiver_tokens_for_caller(db: &AnalyzerDb, caller: FuncId) -> &'static [&'static str] {
    db.global_index()
        .declaring_file(SymbolId::new(caller.raw()))
        .and_then(|file| db.adapter_for(file))
        .map(|adapter| adapter.capabilities().effective_super_receiver_tokens())
        .unwrap_or(bonsai_common::SUPER_RECEIVER_TOKENS)
}

fn super_receiver_tokens_for_decl(db: &AnalyzerDb, decl: &Decl) -> &'static [&'static str] {
    db.global_index()
        .declaring_file(decl.symbol)
        .and_then(|file| db.adapter_for(file))
        .map(|adapter| adapter.capabilities().effective_super_receiver_tokens())
        .unwrap_or(bonsai_common::SUPER_RECEIVER_TOKENS)
}

fn is_super_receiver_for_caller(db: &AnalyzerDb, caller: FuncId, receiver: &str) -> bool {
    is_super_receiver_with_tokens(receiver, super_receiver_tokens_for_caller(db, caller))
}

fn is_super_receiver_for_decl(db: &AnalyzerDb, decl: &Decl, receiver: &str) -> bool {
    is_super_receiver_with_tokens(receiver, super_receiver_tokens_for_decl(db, decl))
}

fn constructor_method_names_for_class(db: &AnalyzerDb, caller: FuncId, class_name: &str) -> Vec<String> {
    let mut out = vec![class_name.to_string()];
    let configured = db
        .global_index()
        .declaring_file(SymbolId::new(caller.raw()))
        .and_then(|file| db.adapter_for(file))
        .map(|adapter| adapter.capabilities().effective_constructor_method_names())
        .unwrap_or(bonsai_common::CONSTRUCTOR_METHOD_NAMES);
    for method in configured {
        if !out.iter().any(|existing| existing == method) {
            out.push((*method).to_string());
        }
    }
    out
}

fn resolved_source_call_assignment(
    event: &FlowEvent,
    config: &InterTaintConfig,
    db: &AnalyzerDb,
    aliases: &AHashMap<String, String>,
    alias_targets: &AHashMap<String, AliasTarget>,
    local_bindings: &AHashMap<String, FuncId>,
    caller: FuncId,
) -> bool {
    let FlowEvent::Assign {
        source_call: Some(callee_name),
        target,
        ..
    } = event
    else {
        return false;
    };
    if target.is_empty() {
        return false;
    }
    !resolve_call_candidates_with_caller(
        callee_name,
        aliases,
        alias_targets,
        local_bindings,
        db,
        caller,
        config,
    )
    .is_empty()
}

fn source_call_assignment_has_independent_tainted_source(
    event: &FlowEvent,
    state: &TokenSet,
    db: Option<&AnalyzerDb>,
    caller: Option<FuncId>,
) -> bool {
    let FlowEvent::Assign {
        source_call: Some(callee_name),
        source_call_args,
        source_names,
        span,
        ..
    } = event
    else {
        return false;
    };
    if !source_call_args.is_empty() {
        return false;
    }
    let qualified_bases = synthetic_qualified_source_bases(source_names, *span, db);
    source_names.iter().any(|name| {
        !call_names_match(name, callee_name)
            && assignment_source_name_is_value_tainted(name, &qualified_bases, db, caller, state)
    })
}

/// Apply state changes that follow an unresolved call when one of
/// its arguments is tainted. The conservative model: prior args
/// whose place is an addressable expression may be mutated by the
/// callee (out-param convention). This is the correct shape for C
/// `T*` parameters, C++ refs, C# `ref`/`out`, Rust `&mut`, Go
/// pointer args — passing `&buf` as a prior arg to a function
/// that's known to write its destination is essential to track
/// configured output-argument flows where the output place is read
/// later in the chain.
///
/// Two precision guards keep this bounded:
///   * Quoted literals never qualify (they cannot be mutated).
///   * The first-tainted-arg cutoff preserves upstream-args-only
///     ordering (tainted arg N can flow back into args 0..N-1 via
///     the callee's body, but not into later args).
///
/// The original adversarial case the user flagged
/// (`args = parse_args(); inner('.category == "electronics"')`)
/// stays clean because the call's tainted_at_call set is empty
/// (the literal arg is not tainted), so this function is never
/// invoked for those flows.
pub(super) fn apply_unresolved_call_side_effects(
    args: &[bonsai_lang_api::CallArg],
    tainted_at_call: &[(usize, String)],
    state: &mut TokenSet,
) -> bool {
    let Some(first_tainted_idx) = tainted_at_call.iter().map(|(idx, _)| *idx).min() else {
        return false;
    };
    let mut changed = false;
    for (idx, arg) in args.iter().enumerate() {
        if idx >= first_tainted_idx {
            continue;
        }
        let Some(place) = arg.place.as_deref() else {
            continue;
        };
        let trimmed = place.trim();
        if trimmed.is_empty() || is_quoted_literal(trimmed) {
            continue;
        }
        let before = state.len();
        insert_value_target_taint(state, trimmed);
        changed |= state.len() != before;
    }
    changed
}

fn unresolved_call_return_is_tainted(callee_name: &str, state: &TokenSet) -> bool {
    state.contains(callee_name)
}

fn event_at_sink_receives_taint(event: &FlowEvent, sink_span: Span, state: &TokenSet) -> bool {
    match event {
        FlowEvent::Call {
            span,
            name,
            receiver,
            args,
            ..
        } if spans_same_site(*span, sink_span) => {
            args.iter().any(|arg| call_arg_is_tainted(arg, state))
                || arg_text_is_tainted(name, state)
                || receiver
                    .as_deref()
                    .is_some_and(|receiver| receiver_expr_is_tainted(receiver, state))
        }
        FlowEvent::Assign {
            span,
            source_name,
            source_names,
            source_call_args,
            ..
        } if spans_same_site(*span, sink_span) => {
            source_name
                .as_deref()
                .is_some_and(|src| arg_text_is_tainted(src, state))
                || source_names.iter().any(|src| arg_text_is_tainted(src, state))
                || source_call_args.iter().any(|src| arg_text_is_tainted(src, state))
        }
        _ => false,
    }
}

fn spans_same_site(a: Span, b: Span) -> bool {
    a.file == b.file && ((a.start == b.start && a.end == b.end) || spans_overlap(a, b))
}

fn spans_overlap(a: Span, b: Span) -> bool {
    a.file == b.file && a.start < b.end && b.start < a.end
}

fn receiver_place_is_tainted(receiver: &str, state: &TokenSet) -> bool {
    let trimmed = receiver.trim();
    if trimmed.is_empty() || is_quoted_literal(trimmed) {
        return false;
    }
    if state.contains(trimmed) || tainted_receiver_access(trimmed, state) {
        return true;
    }
    let normalised = normalise_qualified_text(trimmed);
    normalised != trimmed && (state.contains(&normalised) || tainted_receiver_access(&normalised, state))
}

fn receiver_expr_is_tainted(receiver: &str, state: &TokenSet) -> bool {
    receiver_place_is_tainted(receiver, state)
        || arg_text_has_mapped_descendant_taint(receiver, state)
        || arg_text_is_tainted(receiver, state)
}

// Note: a previous version of this file filtered `type(x)` out of
// receiver propagation as a Python-introspection special case. That
// hard-coded the `type` builtin name in the engine, which violates
// `docs/contributing/taint-engine-spec.mdx` (no library/API table). The check has
// been dropped; conservative receiver-state propagation through
// metadata calls is acceptable. If the over-approximation becomes
// painful, the right fix is an adapter fact on the inner call (a
// `returns_metadata_only` flag on `CallEvent`), not a string match
// here.

pub(super) fn call_receiver_from_name(name: &str) -> Option<String> {
    let normalised = normalise_qualified_text(&name.replace("->", ".").replace("::", "."));
    let (receiver, _) = normalised.rsplit_once('.')?;
    let receiver = receiver.trim();
    (!receiver.is_empty()).then(|| receiver.to_string())
}

fn implicit_receiver_from_call_name(
    name: &str,
    call_kind: bonsai_lang_api::CallKind,
    super_receiver_tokens: &[&str],
) -> Option<String> {
    if call_kind != bonsai_lang_api::CallKind::Method {
        return None;
    }
    let receiver = call_receiver_from_name(name)?;
    let scoped_call = name.contains("::");
    (is_super_receiver_with_tokens(&receiver, super_receiver_tokens)
        || (!scoped_call && matches!(receiver.as_str(), "self" | "this"))
        || (!scoped_call
            && receiver_projects_implicit_receiver(&format!("{receiver}."), super_receiver_tokens)))
    .then_some(receiver)
}

fn caller_implicit_receiver_taint_binding(ctx: &PropagationCtx<'_>, state: &TokenSet) -> Option<String> {
    let global = ctx.db.global_index();
    let caller_decl = global.decl_of(SymbolId::new(ctx.caller.raw()))?;
    receiver_state_names_for_decl(caller_decl)
        .into_iter()
        .filter(|name| receiver_state_name_is_implicit_marker(name))
        .find(|name| receiver_expr_is_tainted(name, state) || actual_has_descendant_taint(name, state))
}

fn receiver_state_name_is_implicit_marker(name: &str) -> bool {
    let bare = normalise_target_text(name)
        .trim_start_matches(&['$', '@', '%'][..])
        .trim()
        .to_string();
    matches!(bare.as_str(), "self" | "this" | "super" | "parent" | "base")
}

fn source_call_name_is_seeded(callee_name: &str, state: &TokenSet) -> bool {
    let normalised = normalise_qualified_text(callee_name);
    if state.contains(callee_name) || (!normalised.is_empty() && state.contains(&normalised)) {
        return true;
    }
    normalised
        .rsplit('.')
        .next()
        .is_some_and(|tail| !tail.is_empty() && state.contains(tail))
}

fn source_call_rhs_is_tainted(
    callee_name: &str,
    source_call_args: &[String],
    source_names: &[String],
    state: &TokenSet,
) -> bool {
    source_call_name_is_seeded(callee_name, state)
        || arg_text_is_tainted(callee_name, state)
        || call_receiver_from_name(callee_name)
            .as_deref()
            .is_some_and(|receiver| {
                source_names.iter().any(|name| {
                    let name = normalise_target_text(name);
                    !name.is_empty() && !text_looks_qualified(&name) && name == receiver
                }) && call_arg_is_directly_tainted(receiver, state)
            })
        || source_call_args.iter().any(|arg| arg_text_is_tainted(arg, state))
}

fn assignment_source_names_any_tainted(
    source_names: &[String],
    span: Span,
    db: Option<&AnalyzerDb>,
    caller: Option<FuncId>,
    state: &TokenSet,
) -> bool {
    if assignment_rhs_text(db, span).is_some_and(|rhs| {
        qualified_accesses(&rhs)
            .iter()
            .any(|access| rhs_operand_is_tainted(access, state))
    }) {
        return true;
    }
    let qualified_bases = synthetic_qualified_source_bases(source_names, span, db);
    source_names
        .iter()
        .any(|name| assignment_source_name_is_value_tainted(name, &qualified_bases, db, caller, state))
}

fn assignment_rhs_is_tainted(rhs: &str, state: &TokenSet) -> bool {
    let rhs = rhs.trim();
    if rhs.is_empty() || is_quoted_literal(rhs) {
        return false;
    }
    if state.contains(rhs) {
        return true;
    }
    let normalised = normalise_qualified_text(rhs);
    let collapsed_to_base = text_looks_qualified(rhs) && !text_looks_qualified(&normalised);
    if normalised != rhs && !collapsed_to_base && rhs_operand_is_tainted(&normalised, state) {
        return true;
    }
    if rhs_operand_is_tainted(rhs, state) {
        return true;
    }
    if receiver_method_projection_is_tainted(rhs, state) {
        return true;
    }
    let qualified_bases = qualified_access_bases(rhs);
    identifier_tokens_outside_strings(&value_bearing_identifier_text(rhs))
        .iter()
        .any(|token| !qualified_bases.iter().any(|base| base == token) && state.contains(token.as_str()))
}

fn assignment_source_name_is_value_tainted(
    name: &str,
    qualified_bases: &AHashSet<String>,
    db: Option<&AnalyzerDb>,
    caller: Option<FuncId>,
    state: &TokenSet,
) -> bool {
    if name.trim().is_empty() {
        return false;
    }
    let canonical = canonical_bare_name(name);
    if qualified_bases.contains(&canonical)
        && !synthetic_carrier_has_scalar_value_type(&canonical, db, caller, state)
    {
        return false;
    }
    rhs_operand_is_tainted(name, state)
}

fn synthetic_carrier_has_scalar_value_type(
    name: &str,
    db: Option<&AnalyzerDb>,
    caller: Option<FuncId>,
    state: &TokenSet,
) -> bool {
    if name.is_empty()
        || !(state.contains(name) || state.contains(&value_marker(name)))
        || text_looks_qualified(name)
    {
        return false;
    }
    let (Some(db), Some(caller)) = (db, caller) else {
        return false;
    };
    let global = db.global_index();
    let Some(decl) = global.decl_of(SymbolId::new(caller.raw())) else {
        return false;
    };
    decl.type_aliases
        .iter()
        .any(|alias| alias.name == name && type_name_is_scalar_value(&alias.type_name))
}

fn type_name_is_scalar_value(type_name: &str) -> bool {
    let type_name = type_name
        .rsplit(&['.', ':'][..])
        .next()
        .unwrap_or(type_name)
        .trim()
        .trim_matches(&['[', ']'][..])
        .to_ascii_lowercase();
    matches!(
        type_name.as_str(),
        "str"
            | "string"
            | "char"
            | "character"
            | "bool"
            | "boolean"
            | "byte"
            | "short"
            | "int"
            | "integer"
            | "long"
            | "float"
            | "double"
            | "decimal"
            | "number"
            | "usize"
            | "isize"
            | "u8"
            | "u16"
            | "u32"
            | "u64"
            | "u128"
            | "i8"
            | "i16"
            | "i32"
            | "i64"
            | "i128"
    )
}

/// Strict per-operand taint check for assignment-RHS `source_names`
/// entries. Adapter-emitted source_names are individual identifier
/// tokens (`["x", "y"]`), normalised qualified targets (`"obj.field"`),
/// or call-site receiver names — never raw expression text. The
/// engine therefore checks them ONLY against state via direct
/// membership / sigil-stripped equivalents / qualified-form
/// normalisation. No tail / base / token-walk fallbacks. If an
/// operand expresses a deeper field navigation, the adapter must
/// surface the qualified form structurally; the engine does not
/// extract it from text.
fn rhs_operand_is_tainted(text: &str, state: &TokenSet) -> bool {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return false;
    }
    if state.contains(trimmed) {
        return true;
    }
    if is_quoted_literal(trimmed) {
        return false;
    }
    let sigil_stripped = trimmed.trim_start_matches(&['$', '@', '%'][..]);
    if sigil_stripped != trimmed && state.contains(sigil_stripped) {
        return true;
    }
    let normalised = normalise_qualified_text(trimmed);
    let collapsed_to_base = text_looks_qualified(trimmed) && !text_looks_qualified(&normalised);
    if normalised != trimmed && !collapsed_to_base && state.contains(&normalised) {
        return true;
    }
    if qualified_wildcard_seed_matches(&normalised, state) {
        return true;
    }
    if receiver_method_projection_is_tainted(trimmed, state) {
        return true;
    }
    if text_looks_qualified(trimmed) {
        if qualified_wildcard_seed_matches(&normalised, state) {
            return true;
        }
        if qualified_accesses(trimmed).iter().any(|access| {
            tainted_receiver_access(access, state) || qualified_wildcard_seed_matches(access, state)
        }) {
            return true;
        }
        // Deeper navigation: `obj.field` → `obj.field.x` reads
        // through the same explicitly-tainted qualified path.
        if state.iter().any(|seed| {
            if !text_looks_qualified(seed) {
                return false;
            }
            let s = normalise_qualified_text(seed);
            !s.is_empty() && normalised.starts_with(&s) && normalised.as_bytes().get(s.len()) == Some(&b'.')
        }) {
            return true;
        }
    }
    false
}

fn call_arg_is_tainted(arg: &CallArg, state: &TokenSet) -> bool {
    arg_text_is_tainted(&arg.value_text, state)
        || arg
            .source_names
            .iter()
            .any(|operand| call_arg_source_operand_is_tainted(&arg.value_text, operand, state))
}

fn call_arg_has_direct_value_taint(arg: &CallArg, state: &TokenSet) -> bool {
    call_arg_is_directly_tainted(&arg.value_text, state)
        || arg
            .source_names
            .iter()
            .any(|operand| call_arg_source_operand_is_tainted(&arg.value_text, operand, state))
}

fn effective_call_arg_is_tainted(arg: &EffectiveCallArg, state: &TokenSet) -> bool {
    arg_text_is_tainted(&arg.value_text, state)
        || arg
            .source_names
            .iter()
            .any(|operand| call_arg_source_operand_is_tainted(&arg.value_text, operand, state))
}

fn effective_call_arg_has_direct_value_taint(arg: &EffectiveCallArg, state: &TokenSet) -> bool {
    call_arg_is_directly_tainted(&arg.value_text, state)
        || arg
            .source_names
            .iter()
            .any(|operand| call_arg_source_operand_is_tainted(&arg.value_text, operand, state))
}

fn effective_call_arg_has_descendant_taint(arg: &EffectiveCallArg, state: &TokenSet) -> bool {
    actual_has_descendant_taint(&arg.value_text, state)
        || arg
            .source_names
            .iter()
            .any(|operand| actual_has_descendant_taint(operand, state))
}

fn call_arg_source_operand_is_tainted(value_text: &str, operand: &str, state: &TokenSet) -> bool {
    let operand_key = canonical_bare_name(operand);
    if operand_key.is_empty() {
        return false;
    }
    let value_text = value_bearing_identifier_text(value_text);
    let structural_base_only = qualified_access_bases(&value_text).iter().any(|base| {
        canonical_bare_name(base) == operand_key && !identifier_value_occurs(&value_text, operand)
    });
    !structural_base_only && rhs_operand_is_tainted(operand, state)
}

/// Decide whether `text` is tainted given the current state.
///
/// The matching strategy is structural-first, with one carefully-
/// scoped textual fallback for compound expression arguments. The
/// strict prerequisite is `is_quoted_literal` short-circuiting to
/// `false` so a fully-quoted-literal arg (the user's reported
/// over-taint case where a hardcoded filter string was reported as
/// tainted) NEVER promotes via any further check.
///
/// Match order:
///   * direct membership of the trimmed text in state,
///   * sigil-stripped identity (`$x` ↔ `x`, `@arr` ↔ `arr`),
///   * normalised qualified form (`obj['k']` ↔ `obj.k`),
///   * tainted receiver access for qualified text (`state has obj.x`
///     → reading `obj.x` or `obj.x.y` matches),
///   * carrier-level taint via bare base of a qualified text,
///   * bare-name read where state holds a qualified seed sharing
///     the same base (call-site arg passing),
///   * compound expression: identifier tokens extracted by the
///     quote-skipping helper [`identifier_tokens_outside_strings`]
///     match against state. This last branch handles
///     `f(prefix + user_input)` etc. — quote-aware, so inside-
///     literal text never produces tokens.
pub(super) fn arg_text_is_tainted(text: &str, state: &TokenSet) -> bool {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return false;
    }
    if is_quoted_literal(trimmed) {
        return false;
    }
    // Strip compile-time/type-only operands before any identity,
    // qualified-access, or token fallback checks. `sizeof(it->node)`
    // mentions `it->node` syntactically, but it does not read the
    // pointer value at runtime and must not make a fixed-size copy
    // look length-tainted.
    let value_text = value_bearing_identifier_text(trimmed);
    let value_trimmed = value_text.trim();
    let stripped_value_free_operand = value_text != trimmed;
    if value_trimmed.is_empty() {
        return false;
    }
    if state.contains(value_trimmed) {
        return true;
    }
    let sigil_stripped = value_trimmed.trim_start_matches(&['$', '@', '%'][..]);
    if sigil_stripped != value_trimmed && state.contains(sigil_stripped) {
        return true;
    }
    let normalised = normalise_qualified_text(value_trimmed);
    let collapsed_to_base = text_looks_qualified(value_trimmed) && !text_looks_qualified(&normalised);
    if normalised != value_trimmed && !collapsed_to_base && state.contains(&normalised) {
        return true;
    }
    if qualified_wildcard_seed_matches(&normalised, state) {
        return true;
    }
    if !stripped_value_free_operand && receiver_method_projection_is_tainted(value_trimmed, state) {
        return true;
    }
    if text_looks_qualified(value_trimmed) {
        if !stripped_value_free_operand && tainted_receiver_access(value_trimmed, state) {
            return true;
        }
        if stripped_value_free_operand
            && qualified_accesses(value_trimmed).iter().any(|access| {
                let normalised_access = normalise_qualified_text(access);
                state.contains(access) || state.contains(&normalised_access)
            })
        {
            return true;
        }
        if !stripped_value_free_operand
            && qualified_accesses(value_trimmed)
                .iter()
                .any(|access| tainted_receiver_access(access, state) || rhs_operand_is_tainted(access, state))
        {
            return true;
        }
    } else if state_qualified_token_matches_text(&normalised, state) {
        return true;
    }
    // Compound expression fallback. Uses the quote-aware tokenizer
    // so identifiers inside string literals are never extracted.
    // Required to recognize `prefix + user_input` shapes when the
    // adapter surfaces the whole expression as the call-arg text.
    let qualified_bases = qualified_access_bases(value_trimmed);
    identifier_tokens_outside_strings(&value_text).iter().any(|tok| {
        let is_qualified_base = qualified_bases.iter().any(|base| base == tok);
        let has_standalone_value_occurrence = identifier_value_occurs(&value_text, tok);
        (!is_qualified_base || has_standalone_value_occurrence) && state.contains(tok.as_str())
    })
}

fn call_arg_is_directly_tainted(text: &str, state: &TokenSet) -> bool {
    if !arg_text_is_tainted(text, state) {
        return false;
    }
    let actual = normalise_target_text(text.trim());
    if actual.is_empty() || text_looks_qualified(&actual) || !is_bare_identifier_text(&actual) {
        return true;
    }
    if state.contains(text.trim()) || state.contains(&actual) || actual_has_value_taint(&actual, state) {
        return true;
    }
    !arg_text_has_mapped_descendant_taint(&actual, state)
}

/// One resolver candidate — a concrete callee FuncId together with
/// the [`EdgeKind`] + [`Precision`] of the edge that reached it.
#[derive(Clone, Debug)]
pub(crate) struct ResolvedCallee {
    func: FuncId,
    kind: EdgeKind,
    precision: Precision,
}

struct CallResolveScope<'a> {
    aliases: &'a AHashMap<String, String>,
    alias_targets: &'a AHashMap<String, AliasTarget>,
    local_bindings: &'a AHashMap<String, FuncId>,
    db: &'a AnalyzerDb,
    caller: FuncId,
    config: &'a InterTaintConfig,
    /// Optional memo cache — callers in the propagation walker
    /// supply `Some` so the resolver doesn't re-walk the same call
    /// site for every source-seeded run. Off-tree callers (summary
    /// builders that already memoise their own results) leave it
    /// `None`.
    resolved_calls: Option<&'a ResolvedCallSiteCache>,
}

impl<'a> CallResolveScope<'a> {
    fn from_ctx(ctx: &'a PropagationCtx<'a>) -> Self {
        Self {
            aliases: ctx.aliases,
            alias_targets: ctx.alias_targets,
            local_bindings: ctx.local_bindings,
            db: ctx.db,
            caller: ctx.caller,
            config: ctx.config,
            resolved_calls: ctx.resolved_calls,
        }
    }
}

fn resolve_call_candidates_with_caller(
    name: &str,
    aliases: &AHashMap<String, String>,
    alias_targets: &AHashMap<String, AliasTarget>,
    local_bindings: &AHashMap<String, FuncId>,
    db: &AnalyzerDb,
    caller: FuncId,
    config: &InterTaintConfig,
) -> Vec<ResolvedCallee> {
    let scope = CallResolveScope {
        aliases,
        alias_targets,
        local_bindings,
        db,
        caller,
        config,
        resolved_calls: None,
    };
    resolve_call_candidates_with_caller_at(name, &scope, &[], None)
}

fn resolve_call_candidates_with_caller_at(
    name: &str,
    scope: &CallResolveScope<'_>,
    receiver_types: &[String],
    call_span: Option<Span>,
) -> Vec<ResolvedCallee> {
    // Memo cache: the resolver answer for `(caller, span)` is purely
    // a function of static AST + symbol-table state, so any
    // source-seeded run that re-walks the same call site shares the
    // same answer. OWASP's 2,740 separate inter-taint runs all walk
    // into `String.format(...)` and friends; without this memo each
    // re-resolves from scratch.
    //
    // Cache only applies when both a cache reference and a stable
    // span identifier are present — call sites that don't supply a
    // span (synthesized resolution from summaries, for example)
    // bypass the cache and run uncached.
    if let (Some(cache), Some(span)) = (scope.resolved_calls, call_span) {
        let key = (scope.caller, span, receiver_types.to_vec());
        // Probe with read lock first; upgrade only on miss. Drop
        // the read guard's temporary at the `;` so the subsequent
        // `.write()` below can't deadlock on a same-thread
        // read→write upgrade (parking_lot RwLock is non-reentrant).
        let cached = cache.read().get(&key).cloned();
        if let Some(arc) = cached {
            return arc.iter().cloned().collect::<Vec<_>>();
        }
        let computed =
            resolve_call_candidates_with_caller_at_uncached(name, scope, receiver_types, call_span);
        let arc: std::sync::Arc<[ResolvedCallee]> = computed.iter().cloned().collect();
        // `or_insert` keeps a winner from a concurrent fill on the
        // same key — engine purity guarantees the values are
        // identical anyway, but pinning the first writer keeps
        // downstream Arc-pointer comparisons stable.
        cache.write().entry(key).or_insert(arc);
        return computed;
    }
    resolve_call_candidates_with_caller_at_uncached(name, scope, receiver_types, call_span)
}

fn resolve_call_candidates_with_caller_at_uncached(
    name: &str,
    scope: &CallResolveScope<'_>,
    receiver_types: &[String],
    call_span: Option<Span>,
) -> Vec<ResolvedCallee> {
    let mut saw_expression_receiver = false;
    let mut saw_super_token_collision_receiver = false;
    let variants = callable_reference_variants(name);
    let original_has_receiver = variants.iter().any(|variant| {
        let normalised = normalise_qualified_text(variant);
        let lookup_name = if normalised.is_empty() {
            variant.as_str()
        } else {
            &normalised
        };
        call_receiver_from_name(lookup_name).is_some()
    });
    let original_alias_qualified = variants.iter().any(|variant| {
        let normalised = normalise_qualified_text(variant);
        let lookup_name = if normalised.is_empty() {
            variant.as_str()
        } else {
            &normalised
        };
        alias_qualified_lookup_name(lookup_name, scope.aliases, scope.alias_targets)
    });
    for variant in variants {
        let normalised = normalise_qualified_text(&variant);
        let lookup_name = if normalised.is_empty() {
            variant.as_str()
        } else {
            &normalised
        };
        let tail = short_tail(lookup_name);
        if original_has_receiver && call_receiver_from_name(lookup_name).is_none() {
            continue;
        }
        let alias_qualified_lookup =
            alias_qualified_lookup_name(lookup_name, scope.aliases, scope.alias_targets);
        if original_alias_qualified && !alias_qualified_lookup {
            continue;
        }
        if let Some(func) = scope
            .local_bindings
            .get(lookup_name)
            .or_else(|| {
                (!alias_qualified_lookup)
                    .then(|| scope.local_bindings.get(tail))
                    .flatten()
            })
            .copied()
        {
            return vec![ResolvedCallee {
                func,
                kind: EdgeKind::Direct,
                precision: Precision::Narrowed,
            }];
        }
        if unqualified_call_name(lookup_name) {
            let exact_targets = resolve_contextual_call_name(lookup_name, scope);
            if !exact_targets.is_empty() {
                return exact_targets;
            }
        }
        if !receiver_types.is_empty() {
            if let Some(receiver) = call_receiver_from_name(lookup_name) {
                let targets = if is_super_receiver_for_caller(scope.db, scope.caller, &receiver) {
                    resolve_super_method_candidates(scope.db, scope.caller, scope.alias_targets, tail)
                } else {
                    resolve_receiver_method_candidates(
                        scope.db,
                        scope.caller,
                        scope.alias_targets,
                        &receiver,
                        receiver_types,
                        tail,
                        call_span,
                    )
                };
                if !targets.is_empty() {
                    return semantic_callees_from_candidates(targets, true);
                }
            }
        }
        if let Some(candidates) = resolve_whole_name_alias_target(lookup_name, scope) {
            if !candidates.is_empty() {
                return semantic_callees_from_candidates(candidates, false);
            }
        }
        if let Some((alias_target, alias_tail)) =
            namespace_alias_target_tail(lookup_name, scope.alias_targets)
        {
            let caller_ctx = caller_resolve_context_data(scope.db, scope.caller);
            let candidates = resolve_workspace_module_targets(
                scope.db,
                alias_target,
                alias_tail,
                caller_ctx.as_ref(),
                scope.alias_targets,
            );
            if !candidates.is_empty() {
                return semantic_callees_from_candidates(candidates, false);
            }
        }
        if let Some(alias_tail) = qualified_alias_tail(lookup_name, scope.aliases) {
            if let Some(alias_target) = alias_head_target(lookup_name, scope.aliases) {
                let caller_ctx = caller_resolve_context_data(scope.db, scope.caller);
                let candidates = resolve_workspace_module_targets(
                    scope.db,
                    alias_target,
                    alias_tail,
                    caller_ctx.as_ref(),
                    scope.alias_targets,
                );
                if !candidates.is_empty() {
                    return semantic_callees_from_candidates(candidates, false);
                }
            }
        }
        if let Some(receiver) = call_receiver_from_name(lookup_name) {
            if is_super_receiver_with_tokens(&receiver, bonsai_common::SUPER_RECEIVER_TOKENS)
                && !is_super_receiver_for_caller(scope.db, scope.caller, &receiver)
            {
                saw_super_token_collision_receiver = true;
            }
            let targets = if is_super_receiver_for_caller(scope.db, scope.caller, &receiver) {
                resolve_super_method_candidates(scope.db, scope.caller, scope.alias_targets, tail)
            } else {
                resolve_receiver_method_candidates(
                    scope.db,
                    scope.caller,
                    scope.alias_targets,
                    &receiver,
                    receiver_types,
                    tail,
                    call_span,
                )
            };
            if !targets.is_empty() {
                return semantic_callees_from_candidates(targets, true);
            }
            if let Some((alias_target, alias_tail)) =
                namespace_alias_target_tail(lookup_name, scope.alias_targets)
            {
                let caller_ctx = caller_resolve_context_data(scope.db, scope.caller);
                let candidates = resolve_workspace_module_targets(
                    scope.db,
                    alias_target,
                    alias_tail,
                    caller_ctx.as_ref(),
                    scope.alias_targets,
                );
                if !candidates.is_empty() {
                    return semantic_callees_from_candidates(candidates, false);
                }
            }
            if let Some(alias_tail) = qualified_alias_tail(lookup_name, scope.aliases) {
                if let Some(alias_target) = alias_head_target(lookup_name, scope.aliases) {
                    let caller_ctx = caller_resolve_context_data(scope.db, scope.caller);
                    let candidates = resolve_workspace_module_targets(
                        scope.db,
                        alias_target,
                        alias_tail,
                        caller_ctx.as_ref(),
                        scope.alias_targets,
                    );
                    if !candidates.is_empty() {
                        return semantic_callees_from_candidates(candidates, false);
                    }
                }
            }
            if let Some(func) = scope.local_bindings.get(receiver.as_str()).copied() {
                let configured_callback =
                    configured_tail_match(&scope.config.callback_invocation_methods, tail);
                if (configured_callback || scope.config.callback_invocation_methods.is_empty())
                    && local_binding_is_callable_value(scope.db, func)
                {
                    return vec![ResolvedCallee {
                        func,
                        kind: EdgeKind::Indirect,
                        precision: Precision::Narrowed,
                    }];
                }
            }
            saw_expression_receiver = true;
            continue;
        }
        let exact_targets = resolve_contextual_call_name(lookup_name, scope);
        if !exact_targets.is_empty() {
            return exact_targets;
        }
    }
    if saw_super_token_collision_receiver {
        return Vec::new();
    }
    if saw_expression_receiver {
        if let Some(method_name) = expression_receiver_method_name(name) {
            let candidates = resolve_unique_untyped_receiver_method_candidate(&method_name, scope);
            if !candidates.is_empty() {
                return candidates;
            }
        }
        return Vec::new();
    }
    resolve_call_candidates(
        name,
        scope.aliases,
        scope.alias_targets,
        scope.db,
        Some(scope.caller),
    )
}

fn resolve_whole_name_alias_target(lookup_name: &str, scope: &CallResolveScope<'_>) -> Option<Vec<FuncId>> {
    let alias_target = scope.alias_targets.get(lookup_name)?;
    let alias_tail = match alias_target {
        AliasTarget::Namespace { .. } => "default",
        AliasTarget::Member { member, .. } => member.as_str(),
        AliasTarget::Type { .. } => return Some(Vec::new()),
    };
    let caller_ctx = caller_resolve_context_data(scope.db, scope.caller);
    Some(resolve_workspace_targets_for_alias_entry(
        scope.db,
        alias_target,
        alias_tail,
        caller_ctx.as_ref(),
        scope.alias_targets,
    ))
}

fn expression_receiver_method_name(name: &str) -> Option<String> {
    callable_reference_variants(name)
        .into_iter()
        .filter_map(|variant| {
            let normalised = normalise_qualified_text(&variant);
            let lookup_name = if normalised.is_empty() {
                variant.as_str()
            } else {
                normalised.as_str()
            };
            call_receiver_from_name(lookup_name).map(|_| short_tail(lookup_name).to_string())
        })
        .find(|method| !method.trim().is_empty())
}

fn resolve_unique_untyped_receiver_method_candidate(
    method_name: &str,
    scope: &CallResolveScope<'_>,
) -> Vec<ResolvedCallee> {
    let global = scope.db.global_index();
    let Some((caller_file, caller_module)) = caller_resolve_context_data(scope.db, scope.caller) else {
        return Vec::new();
    };
    let ctx = ResolveContext::new(caller_file, &caller_module).with_alias_map(scope.alias_targets);
    let candidates = resolve_callable_with_context(&global, method_name, &ctx)
        .into_iter()
        .filter(|func| {
            let Some(decl) = global.decl_of(SymbolId::new(func.raw())) else {
                return false;
            };
            matches!(decl.kind, DeclKind::Method | DeclKind::Constructor)
                || (decl.parent.is_some() && decl.name == method_name)
                || function_decl_uses_qualified_method_name(scope.db, *func, decl, method_name)
        })
        .collect::<Vec<_>>();
    match candidates.as_slice() {
        [func] => vec![ResolvedCallee {
            func: *func,
            kind: EdgeKind::Virtual,
            precision: Precision::Narrowed,
        }],
        _ => Vec::new(),
    }
}

fn function_decl_uses_qualified_method_name(
    db: &AnalyzerDb,
    func: FuncId,
    decl: &Decl,
    method_name: &str,
) -> bool {
    if !matches!(decl.kind, DeclKind::Function) {
        return false;
    }
    let Some(file) = db.global_index().declaring_file(SymbolId::new(func.raw())) else {
        return false;
    };
    let Some(text) = source_text_for_span(db, Span { file, ..decl.span }) else {
        return false;
    };
    let header = text.split_once('(').map_or(text.as_str(), |(head, _)| head);
    [".", ":", "::", "->"]
        .into_iter()
        .any(|sep| header.contains(&format!("{sep}{method_name}")))
}

fn resolve_contextual_call_name(lookup_name: &str, scope: &CallResolveScope<'_>) -> Vec<ResolvedCallee> {
    let global = scope.db.global_index();
    let Some((caller_file, caller_module)) = caller_resolve_context_data(scope.db, scope.caller) else {
        return Vec::new();
    };
    let ctx = ResolveContext::new(caller_file, &caller_module).with_alias_map(scope.alias_targets);
    let mut candidates = resolve_callable_with_context(&global, lookup_name, &ctx);
    if candidates.is_empty() {
        return Vec::new();
    }
    let function_clause_dispatch =
        expand_semantic_function_clause_candidates(scope.db, lookup_name, &ctx, &mut candidates);
    let overload_dispatch =
        function_clause_dispatch || candidates_form_semantic_overload_family(scope.db, &candidates);
    semantic_callees_from_candidates(candidates, overload_dispatch)
}

fn alias_qualified_lookup_name(
    name: &str,
    aliases: &AHashMap<String, String>,
    alias_targets: &AHashMap<String, AliasTarget>,
) -> bool {
    qualified_module_alias_call(name, aliases)
        || split_qualified_head_tail(name)
            .is_some_and(|(head, tail)| !tail.is_empty() && alias_targets.contains_key(head))
}

fn unqualified_call_name(name: &str) -> bool {
    let trimmed = name.trim();
    !trimmed.is_empty()
        && !trimmed.contains('.')
        && !trimmed.contains("::")
        && !trimmed.contains(':')
        && !trimmed.contains('\\')
}

fn unique_narrowed_candidate(candidates: &[ResolvedCallee]) -> Option<FuncId> {
    let [candidate] = candidates else {
        return None;
    };
    (candidate.precision == Precision::Narrowed).then_some(candidate.func)
}

fn semantic_callees_from_candidates(candidates: Vec<FuncId>, allow_virtual: bool) -> Vec<ResolvedCallee> {
    match candidates.as_slice() {
        [] => Vec::new(),
        [func] => vec![ResolvedCallee {
            func: *func,
            kind: EdgeKind::Direct,
            precision: Precision::Narrowed,
        }],
        _ if allow_virtual => candidates
            .into_iter()
            .map(|func| ResolvedCallee {
                func,
                kind: EdgeKind::Virtual,
                precision: Precision::Narrowed,
            })
            .collect(),
        _ => Vec::new(),
    }
}

fn expand_semantic_function_clause_candidates(
    db: &AnalyzerDb,
    lookup_name: &str,
    ctx: &ResolveContext<'_>,
    candidates: &mut Vec<FuncId>,
) -> bool {
    let global = db.global_index();
    let mut expanded = false;
    let lookup_tail = short_tail(lookup_name).trim();
    let seeds = candidates.clone();
    for seed in seeds {
        let Some(seed_decl) = global.decl_of(SymbolId::new(seed.raw())) else {
            continue;
        };
        let Some(seed_file) = global.declaring_file(SymbolId::new(seed.raw())) else {
            continue;
        };
        let Some(adapter) = db.adapter_for(seed_file) else {
            continue;
        };
        if !language_uses_semantic_function_clauses(adapter.language_id().as_str()) {
            continue;
        }
        let family_name = if lookup_tail.is_empty() {
            seed_decl.name.as_str()
        } else {
            lookup_tail
        };
        if family_name != seed_decl.name {
            continue;
        }
        let before_family_len = candidates.len();
        for symbol in global.find_by_name(family_name) {
            let Some(decl) = global.decl_of(*symbol) else {
                continue;
            };
            if !matches!(decl.kind, DeclKind::Function) {
                continue;
            }
            if decl.params.len() != seed_decl.params.len()
                || decl.module_path != seed_decl.module_path
                || decl.name != seed_decl.name
            {
                continue;
            }
            let Some(decl_file) = global.declaring_file(*symbol) else {
                continue;
            };
            if !visibility_allows(decl, decl_file, &decl.module_path, ctx) {
                continue;
            }
            let func = FuncId::new(symbol.raw());
            let before = candidates.len();
            push_unique_func(candidates, func);
            expanded |= candidates.len() != before;
        }
        expanded |= candidates.len() > 1 && candidates.len() >= before_family_len;
    }
    expanded
}

fn language_uses_semantic_function_clauses(language: &str) -> bool {
    matches!(language, "elixir" | "erlang")
}

fn candidates_form_semantic_overload_family(db: &AnalyzerDb, candidates: &[FuncId]) -> bool {
    if candidates.len() <= 1 {
        return false;
    }
    let global = db.global_index();
    let mut family: Option<(String, ModulePath, Option<SymbolId>, String)> = None;
    for func in candidates {
        let symbol = SymbolId::new(func.raw());
        let Some(decl) = global.decl_of(symbol) else {
            return false;
        };
        let Some(file) = global.declaring_file(symbol) else {
            return false;
        };
        let Some(adapter) = db.adapter_for(file) else {
            return false;
        };
        let language = adapter.language_id().as_str().to_string();
        if !language_uses_semantic_overload_family(&language) {
            return false;
        }
        let current = (decl.name.clone(), decl.module_path.clone(), decl.parent, language);
        if let Some(existing) = &family {
            if existing != &current {
                return false;
            }
        } else {
            family = Some(current);
        }
    }
    true
}

fn language_uses_semantic_overload_family(language: &str) -> bool {
    matches!(language, "swift")
}

fn local_binding_is_callable_value(db: &AnalyzerDb, func: FuncId) -> bool {
    let global = db.global_index();
    global
        .decl_of(SymbolId::new(func.raw()))
        .is_some_and(|decl| matches!(decl.kind, DeclKind::Function | DeclKind::Method))
}

fn resolve_receiver_method_candidates(
    db: &AnalyzerDb,
    caller: FuncId,
    alias_targets: &AHashMap<String, AliasTarget>,
    receiver: &str,
    receiver_types: &[String],
    method_name: &str,
    call_span: Option<Span>,
) -> Vec<FuncId> {
    let global = db.global_index();
    let Some(caller_decl) = global.decl_of(SymbolId::new(caller.raw())) else {
        return Vec::new();
    };
    let Some(caller_file) = global.declaring_file(SymbolId::new(caller.raw())) else {
        return Vec::new();
    };
    let mut type_names = receiver_types.to_vec();
    if type_names.is_empty() {
        if let Some(type_name) = type_alias_for_receiver(caller_decl, receiver) {
            push_unique_string(&mut type_names, type_name);
        }
        for type_name in type_alias_targets_for_receiver(alias_targets, receiver) {
            push_unique_string(&mut type_names, type_name);
        }
        for type_name in
            inferred_receiver_type_names(caller_decl, receiver, call_span, db, caller, alias_targets)
        {
            push_unique_string(&mut type_names, type_name);
        }
        for type_name in
            receiver_call_return_type_names(caller_decl, receiver, call_span, db, caller, alias_targets)
        {
            push_unique_string(&mut type_names, type_name);
        }
        for type_name in receiver_constructed_type_names(receiver, db, caller, alias_targets) {
            push_unique_string(&mut type_names, type_name);
        }
    }
    let normalized_receiver = normalise_qualified_text(receiver);
    let receiver_tail = short_tail(&normalized_receiver);
    if matches!(receiver_tail, "self" | "this") {
        if let Some(class_decl) = enclosing_class_for_decl(&global, caller_decl) {
            push_unique_string(&mut type_names, class_decl.name.clone());
        }
    }
    if receiver_projects_implicit_receiver(receiver, super_receiver_tokens_for_caller(db, caller)) {
        if let Some(class_decl) = enclosing_class_for_decl(&global, caller_decl) {
            for base in &class_decl.bases {
                push_unique_string(&mut type_names, base.clone());
            }
        }
    }
    let caller_module = caller_decl.module_path.clone();
    let path_lookup = |file| {
        db.vfs()
            .path(file)
            .ok()
            .map(|path| path.to_string_lossy().into_owned())
    };
    let class_ctx = ResolveContext::new(caller_file, &caller_module)
        .with_alias_map(alias_targets)
        .with_file_path_lookup(&path_lookup);
    if type_names.is_empty() {
        return Vec::new();
    }
    // Class lookup via the semantic-identity resolver: filters by
    // caller visibility and (when adapters populate it) module_path.
    // Per `docs/contributing/design-patterns.mdx::Semantic Resolution Always`.
    let type_names = prune_receiver_type_names_for_dispatch(type_names, &global, &class_ctx);
    let mut out = Vec::new();
    let mut seen = AHashSet::new();
    for type_name in type_names {
        for class_sym in resolve_class(&global, &type_name, &class_ctx) {
            collect_method_candidates_for_class(
                &global,
                class_sym,
                method_name,
                &class_ctx,
                &mut seen,
                &mut out,
            );
        }
    }
    out
}

// Class-dispatch helpers live in `bonsai_resolve` so the callgraph
// and taint engine consume one source of truth.

fn type_alias_for_receiver(decl: &Decl, receiver: &str) -> Option<String> {
    use bonsai_common::REFERENCE_SIGILS;
    let normalized = normalise_qualified_text(receiver)
        .trim_start_matches(REFERENCE_SIGILS)
        .trim()
        .trim_matches('.')
        .to_string();
    let tail = short_tail(&normalized);
    let self_tail = format!("self.{tail}");
    let this_tail = format!("this.{tail}");
    decl.type_aliases
        .iter()
        .find(|alias| {
            alias.name == receiver
                || alias.name == normalized
                || alias.name == tail
                || alias.name == self_tail
                || alias.name == this_tail
        })
        .map(|alias| alias.type_name.clone())
}

fn type_alias_targets_for_receiver(
    alias_targets: &AHashMap<String, AliasTarget>,
    receiver: &str,
) -> Vec<String> {
    use bonsai_common::REFERENCE_SIGILS;
    let normalized = normalise_qualified_text(receiver)
        .trim_start_matches(REFERENCE_SIGILS)
        .trim()
        .trim_matches('.')
        .to_string();
    let tail = short_tail(&normalized);
    let self_tail = format!("self.{tail}");
    let this_tail = format!("this.{tail}");
    let mut out = Vec::new();
    for key in [
        receiver,
        normalized.as_str(),
        tail,
        self_tail.as_str(),
        this_tail.as_str(),
    ] {
        if let Some(AliasTarget::Type { type_name }) = alias_targets.get(key) {
            push_unique_string(&mut out, type_name.clone());
        }
    }
    out
}

fn receiver_projects_implicit_receiver(receiver: &str, super_receiver_tokens: &[&str]) -> bool {
    use bonsai_common::IMPLICIT_RECEIVER_PREFIXES;
    let receiver = normalise_qualified_text(receiver);
    IMPLICIT_RECEIVER_PREFIXES
        .iter()
        .any(|prefix| receiver.starts_with(*prefix))
        || super_receiver_tokens
            .iter()
            .any(|token| receiver.starts_with(&format!("{token}.")))
}

fn resolve_super_method_candidates(
    db: &AnalyzerDb,
    caller: FuncId,
    alias_targets: &AHashMap<String, AliasTarget>,
    method_name: &str,
) -> Vec<FuncId> {
    let global = db.global_index();
    let Some(caller_decl) = global.decl_of(SymbolId::new(caller.raw())) else {
        return Vec::new();
    };
    let Some(caller_file) = global.declaring_file(SymbolId::new(caller.raw())) else {
        return Vec::new();
    };
    let Some(class_decl) = enclosing_class_for_decl(&global, caller_decl) else {
        return Vec::new();
    };
    let path_lookup = |file| {
        db.vfs()
            .path(file)
            .ok()
            .map(|path| path.to_string_lossy().into_owned())
    };
    let ctx = ResolveContext::new(caller_file, &caller_decl.module_path)
        .with_alias_map(alias_targets)
        .with_file_path_lookup(&path_lookup);
    let mut out = Vec::new();
    let mut seen = AHashSet::new();
    for base in &class_decl.bases {
        for class_sym in resolve_class(&global, base, &ctx) {
            collect_method_candidates_for_class(&global, class_sym, method_name, &ctx, &mut seen, &mut out);
        }
    }
    out
}

fn inferred_receiver_type_names(
    caller_decl: &Decl,
    receiver: &str,
    call_span: Option<Span>,
    db: &AnalyzerDb,
    caller: FuncId,
    alias_targets: &AHashMap<String, AliasTarget>,
) -> Vec<String> {
    let mut out = Vec::new();
    collect_receiver_type_names_from_events(
        &caller_decl.flow_events,
        receiver,
        call_span,
        db,
        caller,
        alias_targets,
        &mut out,
    );
    out
}

fn receiver_call_return_type_names(
    caller_decl: &Decl,
    receiver: &str,
    _call_span: Option<Span>,
    db: &AnalyzerDb,
    caller: FuncId,
    alias_targets: &AHashMap<String, AliasTarget>,
) -> Vec<String> {
    let mut out = receiver_constructed_type_names(receiver, db, caller, alias_targets);
    let Some(inner_call) = receiver_inner_call_name(receiver) else {
        return out;
    };
    for type_name in receiver_constructed_type_names(&inner_call, db, caller, alias_targets) {
        push_unique_string(&mut out, type_name);
    }
    let global = db.global_index();
    let Some(caller_file) = global.declaring_file(SymbolId::new(caller.raw())) else {
        return out;
    };
    let path_lookup = |file| {
        db.vfs()
            .path(file)
            .ok()
            .map(|path| path.to_string_lossy().into_owned())
    };
    let ctx = ResolveContext::new(caller_file, &caller_decl.module_path)
        .with_alias_map(alias_targets)
        .with_file_path_lookup(&path_lookup);
    let mut funcs = Vec::new();
    let mut late_static_type: Option<String> = None;
    if let Some(receiver_name) = call_receiver_from_name(&inner_call) {
        let method_name = callee_without_call_args(short_tail(&inner_call));
        let receiver_type = short_tail(&receiver_name).trim_end_matches("()").to_string();
        if !receiver_type.is_empty() {
            late_static_type = Some(receiver_type.clone());
        }
        if !receiver_type.is_empty() && !resolve_class(&global, &receiver_type, &ctx).is_empty() {
            let mut seen = AHashSet::new();
            for class_sym in resolve_class(&global, &receiver_type, &ctx) {
                collect_method_candidates_for_class(
                    &global,
                    class_sym,
                    method_name,
                    &ctx,
                    &mut seen,
                    &mut funcs,
                );
            }
        }
    } else {
        for func in resolve_callable_with_context(&global, &inner_call, &ctx) {
            push_unique_func(&mut funcs, func);
        }
    }
    for func in funcs {
        let Some(decl) = global.decl_of(SymbolId::new(func.raw())) else {
            continue;
        };
        collect_constructed_return_type_names(
            decl,
            db,
            caller,
            alias_targets,
            late_static_type.as_deref(),
            &mut out,
        );
    }
    out
}

fn receiver_constructed_type_names(
    receiver: &str,
    db: &AnalyzerDb,
    caller: FuncId,
    alias_targets: &AHashMap<String, AliasTarget>,
) -> Vec<String> {
    let mut out = Vec::new();
    for candidate in constructed_type_candidates(receiver) {
        if class_like_constructor_call(&candidate, db, caller, alias_targets) {
            push_unique_string(&mut out, short_tail(&candidate).to_string());
        }
    }
    out
}

/// Extract the inner call name from a `Foo.bar(args)`-shaped
/// receiver. The taint engine uses the bracket-depth-aware
/// [`normalise_qualified_text`] because its inputs are post-
/// concatenation FlowEvent expression texts (`obj['k'].bar()` ->
/// `obj.k.bar()`); callgraph's shape-equivalent helper uses the
/// simpler `normalize_receiver_alias_text` because its input is
/// already structured.
fn receiver_inner_call_name(receiver: &str) -> Option<String> {
    let receiver = normalise_qualified_text(receiver);
    let receiver = receiver.trim();
    if !receiver.ends_with(')') {
        return None;
    }
    let open = receiver.find('(')?;
    let callee = receiver[..open].trim();
    if callee.is_empty() || callee.contains('"') || callee.contains('\'') || callee.contains('`') {
        return None;
    }
    Some(callee.to_string())
}

fn collect_constructed_return_type_names(
    decl: &Decl,
    db: &AnalyzerDb,
    caller: FuncId,
    alias_targets: &AHashMap<String, AliasTarget>,
    late_static_type: Option<&str>,
    out: &mut Vec<String>,
) {
    collect_constructed_return_type_names_from_events(
        decl,
        late_static_type,
        &decl.flow_events,
        db,
        caller,
        alias_targets,
        out,
    );
}

fn collect_constructed_return_type_names_from_events(
    decl: &Decl,
    late_static_type: Option<&str>,
    events: &[FlowEvent],
    db: &AnalyzerDb,
    caller: FuncId,
    alias_targets: &AHashMap<String, AliasTarget>,
    out: &mut Vec<String>,
) {
    for event in events {
        match event {
            FlowEvent::Return {
                value_text: Some(value_text),
                ..
            } => {
                if let Some(type_name) =
                    constructed_return_type_from_text(value_text, db, caller, alias_targets)
                {
                    push_unique_string(out, type_name);
                } else if bonsai_common::value_text_returns_self_constructor(value_text) {
                    let global = db.global_index();
                    if let Some(type_name) = late_static_type {
                        push_unique_string(out, type_name.to_string());
                    } else if let Some(parent) = decl.parent.and_then(|symbol| global.decl_of(symbol)) {
                        push_unique_string(out, parent.name.clone());
                    }
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                collect_constructed_return_type_names_from_events(
                    decl,
                    late_static_type,
                    then_events,
                    db,
                    caller,
                    alias_targets,
                    out,
                );
                collect_constructed_return_type_names_from_events(
                    decl,
                    late_static_type,
                    else_events,
                    db,
                    caller,
                    alias_targets,
                    out,
                );
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                collect_constructed_return_type_names_from_events(
                    decl,
                    late_static_type,
                    body,
                    db,
                    caller,
                    alias_targets,
                    out,
                );
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                collect_constructed_return_type_names_from_events(
                    decl,
                    late_static_type,
                    body,
                    db,
                    caller,
                    alias_targets,
                    out,
                );
                collect_constructed_return_type_names_from_events(
                    decl,
                    late_static_type,
                    catch_events,
                    db,
                    caller,
                    alias_targets,
                    out,
                );
                collect_constructed_return_type_names_from_events(
                    decl,
                    late_static_type,
                    finally_events,
                    db,
                    caller,
                    alias_targets,
                    out,
                );
            }
            _ => {}
        }
    }
}

fn constructed_return_type_from_text(
    value_text: &str,
    db: &AnalyzerDb,
    caller: FuncId,
    alias_targets: &AHashMap<String, AliasTarget>,
) -> Option<String> {
    constructed_type_name_from_expr(value_text, db, caller, alias_targets)
}

fn constructed_type_name_from_expr(
    value_text: &str,
    db: &AnalyzerDb,
    caller: FuncId,
    alias_targets: &AHashMap<String, AliasTarget>,
) -> Option<String> {
    let mut text = value_text.trim();
    for keyword in bonsai_common::VALUE_TEXT_LEADING_KEYWORDS {
        text = text.strip_prefix(*keyword).unwrap_or(text).trim();
    }
    for candidate in constructed_type_candidates(text) {
        if class_like_constructor_call(&candidate, db, caller, alias_targets) {
            return Some(short_tail(&candidate).to_string());
        }
    }
    None
}

fn constructed_type_candidates(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    push_constructed_type_candidate(text, &mut out);
    let normalised = normalise_qualified_text(&text.replace("::", "."));
    push_constructed_type_candidate(&normalised, &mut out);
    out
}

fn push_constructed_type_candidate(text: &str, out: &mut Vec<String>) {
    let mut candidate = strip_outer_parens(text.trim());
    for keyword in bonsai_common::VALUE_TEXT_LEADING_KEYWORDS {
        candidate = candidate.strip_prefix(*keyword).unwrap_or(candidate).trim();
    }
    if let Some(rest) = candidate.strip_prefix("new ") {
        candidate = rest.trim();
    }
    candidate = strip_outer_parens(candidate);
    if let Some(open) = candidate.find('(') {
        candidate = candidate[..open].trim();
    }
    candidate = candidate.trim_end_matches("()").trim();
    if let Some(owner) = candidate
        .strip_suffix(".new")
        .or_else(|| candidate.strip_suffix("::new"))
        .or_else(|| candidate.strip_suffix("->new"))
        .map(str::trim)
        .filter(|owner| !owner.is_empty())
    {
        candidate = owner;
    }
    if candidate.is_empty() || !call_name_looks_type_constructor(candidate) {
        return;
    }
    let value = candidate.to_string();
    if !out.iter().any(|existing| existing == &value) {
        out.push(value);
    }
}

fn strip_outer_parens(mut text: &str) -> &str {
    loop {
        let trimmed = text.trim();
        if !(trimmed.starts_with('(') && trimmed.ends_with(')') && trimmed.len() > 1) {
            return trimmed;
        }
        text = &trimmed[1..trimmed.len() - 1];
    }
}

fn collect_receiver_type_names_from_events(
    events: &[FlowEvent],
    receiver: &str,
    call_span: Option<Span>,
    db: &AnalyzerDb,
    caller: FuncId,
    alias_targets: &AHashMap<String, AliasTarget>,
    out: &mut Vec<String>,
) {
    let receiver = normalise_target_text(receiver);
    for event in events {
        match event {
            FlowEvent::Assign {
                target,
                source_name,
                source_call,
                source_names,
                span,
                ..
            } => {
                if call_span.is_some_and(|call_span| span.start > call_span.start) {
                    continue;
                }
                if normalise_target_text(target) != receiver {
                    continue;
                }
                if let Some(source_call) = source_call {
                    let global = db.global_index();
                    if let Some(caller_decl) = global.decl_of(SymbolId::new(caller.raw())) {
                        for type_name in receiver_call_return_type_names(
                            caller_decl,
                            &format!("{source_call}()"),
                            Some(*span),
                            db,
                            caller,
                            alias_targets,
                        ) {
                            push_unique_string(out, type_name);
                        }
                    }
                }
                for candidate in source_call
                    .iter()
                    .chain(source_name.iter())
                    .chain(source_names.iter())
                {
                    let candidate = normalise_qualified_text(candidate);
                    if let Some(type_name) =
                        constructed_type_name_from_expr(&candidate, db, caller, alias_targets)
                    {
                        push_unique_string(out, type_name);
                        continue;
                    }
                    if candidate.is_empty() || !call_name_looks_type_constructor(&candidate) {
                        for token in identifier_tokens_outside_strings(&candidate) {
                            if let Some(type_name) =
                                constructed_type_name_from_expr(&token, db, caller, alias_targets)
                            {
                                push_unique_string(out, type_name);
                            }
                        }
                        continue;
                    }
                    if class_like_constructor_call(&candidate, db, caller, alias_targets) {
                        push_unique_string(out, short_tail(&candidate).to_string());
                    }
                }
                collect_constructor_call_types_in_span(
                    events,
                    *span,
                    call_span,
                    db,
                    caller,
                    alias_targets,
                    out,
                );
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                collect_receiver_type_names_from_events(
                    then_events,
                    &receiver,
                    call_span,
                    db,
                    caller,
                    alias_targets,
                    out,
                );
                collect_receiver_type_names_from_events(
                    else_events,
                    &receiver,
                    call_span,
                    db,
                    caller,
                    alias_targets,
                    out,
                );
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                collect_receiver_type_names_from_events(
                    body,
                    &receiver,
                    call_span,
                    db,
                    caller,
                    alias_targets,
                    out,
                );
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                collect_receiver_type_names_from_events(
                    body,
                    &receiver,
                    call_span,
                    db,
                    caller,
                    alias_targets,
                    out,
                );
                collect_receiver_type_names_from_events(
                    catch_events,
                    &receiver,
                    call_span,
                    db,
                    caller,
                    alias_targets,
                    out,
                );
                collect_receiver_type_names_from_events(
                    finally_events,
                    &receiver,
                    call_span,
                    db,
                    caller,
                    alias_targets,
                    out,
                );
            }
            _ => {}
        }
    }
}

fn collect_constructor_call_types_in_span(
    events: &[FlowEvent],
    assign_span: Span,
    call_span: Option<Span>,
    db: &AnalyzerDb,
    caller: FuncId,
    alias_targets: &AHashMap<String, AliasTarget>,
    out: &mut Vec<String>,
) {
    for event in events {
        match event {
            FlowEvent::Call { name, span, .. } => {
                if span.start < assign_span.start || span.end > assign_span.end {
                    continue;
                }
                if call_span.is_some_and(|call_span| span.start > call_span.start) {
                    continue;
                }
                let candidate = normalise_qualified_text(name);
                if let Some(type_name) =
                    constructed_type_name_from_expr(&candidate, db, caller, alias_targets)
                {
                    push_unique_string(out, type_name);
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                collect_constructor_call_types_in_span(
                    then_events,
                    assign_span,
                    call_span,
                    db,
                    caller,
                    alias_targets,
                    out,
                );
                collect_constructor_call_types_in_span(
                    else_events,
                    assign_span,
                    call_span,
                    db,
                    caller,
                    alias_targets,
                    out,
                );
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                collect_constructor_call_types_in_span(
                    body,
                    assign_span,
                    call_span,
                    db,
                    caller,
                    alias_targets,
                    out,
                );
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                collect_constructor_call_types_in_span(
                    body,
                    assign_span,
                    call_span,
                    db,
                    caller,
                    alias_targets,
                    out,
                );
                collect_constructor_call_types_in_span(
                    catch_events,
                    assign_span,
                    call_span,
                    db,
                    caller,
                    alias_targets,
                    out,
                );
                collect_constructor_call_types_in_span(
                    finally_events,
                    assign_span,
                    call_span,
                    db,
                    caller,
                    alias_targets,
                    out,
                );
            }
            _ => {}
        }
    }
}

pub(super) use bonsai_resolve::push_unique_string;

fn alias_targets_for_decl(
    imports: &[bonsai_lang_api::ImportSpec],
    decl: &Decl,
) -> AHashMap<String, AliasTarget> {
    let mut map: AHashMap<String, AliasTarget> = bonsai_lang_api::alias_map_from_import_specs(imports)
        .into_iter()
        .collect();
    extend_alias_targets_with_declared_types(&mut map, &decl.type_aliases);
    bonsai_lang_api::extend_alias_map_with_flow_events(&mut map, &decl.flow_events);
    map
}

/// Caller-side resolve context derived from `caller`. Returns the
/// caller's declaring file and a borrow into its `Decl.module_path`,
/// which the resolver consults for visibility filtering. When the
/// caller decl has not been indexed yet, callers must return no edge
/// rather than falling back to a workspace-wide bare-name lookup.
fn caller_resolve_context_data(db: &AnalyzerDb, caller: FuncId) -> Option<(FileId, ModulePath)> {
    let global = db.global_index();
    let sym = SymbolId::new(caller.raw());
    let file = global.declaring_file(sym)?;
    let decl = global.decl_of(sym)?;
    // Clone the module_path so callers can build ResolveContext
    // without juggling lifetimes against the global lock.
    Some((file, decl.module_path.clone()))
}

/// Resolve a call name to its candidate callees, applying the
/// caller-file alias map. Unique candidates become Direct/Narrowed;
/// ambiguous multi-candidate sets return no edge unless an earlier
/// receiver-specific path already narrowed them semantically.
///
/// When `caller` is `Some`, resolution narrows by the caller's
/// `Visibility` / `module_path` context per
/// `docs/contributing/design-patterns.mdx::Semantic Resolution Always`. When
/// `None` (worklist seeding before any caller is known), returns no
/// candidates instead of falling back to a workspace-wide bare-name
/// lookup.
fn resolve_call_candidates(
    name: &str,
    aliases: &AHashMap<String, String>,
    alias_targets: &AHashMap<String, AliasTarget>,
    db: &AnalyzerDb,
    caller: Option<FuncId>,
) -> Vec<ResolvedCallee> {
    let global = db.global_index();
    let normalised = normalise_qualified_text(name);
    let lookup_name = if normalised.is_empty() { name } else { &normalised };
    let caller_ctx = caller.and_then(|c| caller_resolve_context_data(db, c));
    let lookup = |needle: &str| -> Vec<FuncId> {
        let Some((caller_file, caller_module)) = &caller_ctx else {
            return Vec::new();
        };
        let ctx = ResolveContext::new(*caller_file, caller_module).with_alias_map(alias_targets);
        resolve_callable_with_context(&global, needle, &ctx)
    };
    let mut candidates = lookup(lookup_name);
    if !candidates.is_empty() {
        return semantic_callees_from_candidates(candidates, false);
    }
    if let Some(alias_target) = alias_targets.get(lookup_name) {
        let alias_tail = match alias_target {
            AliasTarget::Namespace { .. } => Some("default"),
            AliasTarget::Member { member, .. } => Some(member.as_str()),
            AliasTarget::Type { .. } => None,
        };
        if let Some(alias_tail) = alias_tail {
            let candidates = resolve_workspace_targets_for_alias_entry(
                db,
                alias_target,
                alias_tail,
                caller_ctx.as_ref(),
                alias_targets,
            );
            if !candidates.is_empty() {
                return semantic_callees_from_candidates(candidates, false);
            }
        }
    }
    if is_single_colon_qualified(lookup_name) {
        let Some((module, function)) = lookup_name.split_once(':') else {
            return Vec::new();
        };
        // Per docs/contributing/design-patterns.mdx::Semantic Resolution Always: even
        // single-colon-qualified callee resolution must apply the
        // caller's visibility / module_path filter. The file-stem
        // narrowing below is a syntactic refinement on top, not a
        // substitute for context-aware lookup.
        let candidates = lookup(function)
            .into_iter()
            .filter(|func| {
                let symbol = SymbolId::new(func.raw());
                global
                    .declaring_file(symbol)
                    .and_then(|file| db.vfs().path(file).ok())
                    .and_then(|path| path.file_stem().map(|stem| stem.to_string_lossy().into_owned()))
                    .is_some_and(|stem| stem == module)
            })
            .collect::<Vec<_>>();
        if candidates.is_empty() {
            return Vec::new();
        }
        return semantic_callees_from_candidates(candidates, false);
    }
    // External-module check FIRST — match `bonsai_callgraph` ordering
    // so identical alias maps produce identical resolution decisions
    // across the engine. If `head` names a known import alias and
    // the call shape is `head.fn(...)`, we know the target is
    // external; only the rewritten `{alias_target}.{alias_tail}` form
    // could plausibly resolve to a workspace decl.
    let module_alias_call = qualified_module_alias_call(lookup_name, aliases);
    if let Some(alias_tail) = qualified_alias_tail(lookup_name, aliases) {
        let alias_target = alias_head_target(lookup_name, aliases);
        let alias_head = split_qualified_head_tail(lookup_name).map(|(h, _)| h);
        if let Some(target) = alias_target {
            // Pass the caller's resolve context so workspace-module
            // export resolution narrows by Visibility / module_path —
            // per docs/contributing/design-patterns.mdx::Semantic Resolution Always.
            candidates =
                resolve_workspace_module_targets(db, target, alias_tail, caller_ctx.as_ref(), alias_targets);
        }
        // Self-binding aliases (e.g. Go `import "fmt"` →
        // alias_target `fmt`, alias_head `fmt`) and path-style
        // aliases (`import "io/fs"` → alias_target `io/fs`) both
        // identify the head as an external package — UNLESS the
        // head also names a workspace decl (Rust `use foo::{self}`
        // where `foo` is an in-workspace module re-export). The
        // workspace probe distinguishes "Go-style external
        // package" from "in-workspace re-export self-binding"; a
        // false positive on the latter would suppress bare-tail
        // and rewrite resolution and break cross-module taint.
        let alias_is_self_binding = alias_target.zip(alias_head).is_some_and(|(t, h)| t == h);
        let alias_is_path_style = alias_target.is_some_and(|t| t.contains('/'));
        // A self-binding or path-style import (`fmt.Println`,
        // `io/fs.ReadDir`) must resolve through the alias target or
        // remain unresolved. A same-named workspace type/class is not
        // evidence that the imported package selector can fall back to
        // the bare tail.
        let alias_marks_external = alias_is_self_binding || alias_is_path_style;
        if candidates.is_empty() && !alias_marks_external {
            candidates = lookup(alias_tail);
        }
        if candidates.is_empty() && !alias_is_self_binding {
            // Skip the rewrite for external-package self-bindings —
            // `{fmt}.{Println}` is byte-identical to the bare
            // `fmt.Println` we already tried at the top of the
            // function. Path-style aliases (e.g. `io/fs`) still try
            // the rewrite because `io/fs.ReadDir` differs from the
            // original call shape.
            if let Some(target) = alias_target {
                let rewritten = format!("{target}.{alias_tail}");
                candidates = lookup(&rewritten);
            }
        }
        if !candidates.is_empty() {
            return semantic_callees_from_candidates(candidates, false);
        }
    }
    let alias_target_qualified_call = alias_qualified_lookup_name(lookup_name, aliases, alias_targets);
    if module_alias_call || alias_target_qualified_call {
        return Vec::new();
    }
    let tail = short_tail(lookup_name);
    let resolved_name = aliases.get(tail).map(String::as_str).unwrap_or(tail);
    candidates = lookup(resolved_name);
    if candidates.is_empty() && resolved_name != lookup_name {
        candidates = lookup(lookup_name);
    }
    if candidates.is_empty() && lookup_name != name {
        candidates = lookup(name);
    }
    if candidates.is_empty() {
        return Vec::new();
    }
    // `lookup` is `resolve_callable_with_context` which already
    // applies visibility + module + receiver-type narrowing — so
    // when exactly one candidate survives, the call IS direct
    // regardless of which lookup name produced the hit. Only the
    // multi-candidate case is ambiguous and produces no flow. The
    // earlier `used_tail_fallback` widening was a vestigial guard.
    semantic_callees_from_candidates(candidates, false)
}

/// True when `name` uses a single-colon module qualifier (e.g.
/// `Module:function`). This is a SYNTACTIC test — no language
/// name-tables. Adapters that emit this shape (currently Erlang;
/// could be any future language using the same convention) get
/// candidate filtering by file-stem match in the caller, which
/// is itself syntax-driven (filesystem convention) and not a
/// hardcoded library list.
fn is_single_colon_qualified(name: &str) -> bool {
    name.contains(':') && !name.contains("::")
}

fn qualified_alias_tail<'a>(name: &'a str, aliases: &AHashMap<String, String>) -> Option<&'a str> {
    let (head, tail) = split_qualified_head_tail(name)?;
    aliases.contains_key(head).then_some(tail)
}

fn alias_head_target<'a>(name: &'a str, aliases: &'a AHashMap<String, String>) -> Option<&'a str> {
    let (head, _) = split_qualified_head_tail(name)?;
    aliases.get(head).map(String::as_str)
}

fn resolve_workspace_module_targets(
    db: &AnalyzerDb,
    alias_target: &str,
    alias_tail: &str,
    caller_ctx: Option<&(FileId, ModulePath)>,
    alias_targets: &AHashMap<String, AliasTarget>,
) -> Vec<FuncId> {
    if alias_target.is_empty() || alias_tail.is_empty() {
        return Vec::new();
    }
    let global = db.global_index();
    let mut seen_spans = AHashSet::new();
    let mut out = Vec::new();
    // Per docs/contributing/design-patterns.mdx::Semantic Resolution Always:
    // no caller context means no edge. Falling back to bare-name
    // lookup can stitch together unrelated workspace functions.
    let Some((caller_file, caller_module)) = caller_ctx else {
        return Vec::new();
    };
    let resolve_ctx = ResolveContext::new(*caller_file, caller_module).with_alias_map(alias_targets);
    let caller_export_aliases = caller_ctx
        .and_then(|(file, _)| db.adapter_for(*file))
        .map(|adapter| adapter.capabilities().module_export_aliases)
        .unwrap_or(&[]);
    for func in export_name_variants(alias_tail, caller_export_aliases)
        .into_iter()
        .flat_map(|name| collect_workspace_callable_targets_by_name(&global, &name, &resolve_ctx))
    {
        let sym = SymbolId::new(func.raw());
        let Some(file) = global.declaring_file(sym) else {
            continue;
        };
        let Some(decl) = global.decl_of(sym) else {
            continue;
        };
        // Match via the decl's semantic module_path first — for
        // languages like Elixir whose modules are PascalCase but
        // files are snake_case (`MyApp.AuthService` ↔
        // `my_app/auth_service.ex`), the file-path heuristic in
        // `module_target_matches_path` cannot recover the
        // workspace-module identity. The adapter populates
        // `Decl.module_path` with the canonical module segments,
        // and a dotted-form match against `alias_target` is the
        // semantic-identity test the resolver should prefer.
        let semantic_match = module_target_matches_decl_module_path(alias_target, &decl.module_path);
        let in_target_file = semantic_match
            || db
                .vfs()
                .path(file)
                .ok()
                .is_some_and(|path: std::sync::Arc<std::path::PathBuf>| {
                    module_target_matches_path(alias_target, &path.to_string_lossy())
                });
        if !in_target_file {
            continue;
        }
        if seen_spans.insert((file, decl.span.start, decl.span.end)) {
            out.push(func);
        }
    }
    out
}

fn resolve_workspace_targets_for_alias_entry(
    db: &AnalyzerDb,
    alias_target: &AliasTarget,
    alias_tail: &str,
    caller_ctx: Option<&(FileId, ModulePath)>,
    alias_targets: &AHashMap<String, AliasTarget>,
) -> Vec<FuncId> {
    match alias_target {
        AliasTarget::Namespace { module } => {
            resolve_workspace_module_targets(db, module, alias_tail, caller_ctx, alias_targets)
        }
        AliasTarget::Member { module, member } => {
            let mut out = resolve_workspace_module_targets(db, module, alias_tail, caller_ctx, alias_targets);
            if out.is_empty() {
                out = resolve_workspace_module_targets(db, member, alias_tail, caller_ctx, alias_targets);
            }
            out
        }
        AliasTarget::Type { .. } => Vec::new(),
    }
}

fn collect_workspace_callable_targets_by_name(
    global: &bonsai_index::GlobalIndex,
    name: &str,
    resolve_ctx: &ResolveContext<'_>,
) -> Vec<FuncId> {
    global
        // CONTEXTLESS_LOOKUP_JUSTIFICATION: workspace-module import
        // resolution first selects decls by imported member name,
        // then immediately constrains candidates by visibility and by
        // the imported module/file target before emitting any edge.
        .find_by_name(name)
        .iter()
        .filter_map(|symbol| {
            let decl = global.decl_of(*symbol)?;
            let file = global.declaring_file(*symbol)?;
            Some((decl, file))
        })
        .filter(|(decl, file)| {
            matches!(
                decl.kind,
                DeclKind::Function | DeclKind::Method | DeclKind::Constructor
            ) && visibility_allows(decl, *file, &decl.module_path, resolve_ctx)
        })
        .map(|(decl, _)| FuncId::new(decl.symbol.raw()))
        .collect()
}

/// Apply one event's taint transfer to `state`. Mirror of the
/// per-event transfer function inside [`crate::intra`] — duplicated
/// here because the inter layer walks events with a custom mid-
/// block step-through cursor that the intra layer doesn't expose.
#[allow(clippy::single_match)] // preserved as `match` for parity with sibling event-walks
pub(super) fn apply_event_transfer(
    event: &FlowEvent,
    state: &mut TokenSet,
    config: &InterTaintConfig,
    db: Option<&AnalyzerDb>,
    caller: Option<FuncId>,
) {
    apply_event_transfer_with_options(event, state, config, db, caller, false);
}

fn apply_event_transfer_with_options(
    event: &FlowEvent,
    state: &mut TokenSet,
    _config: &InterTaintConfig,
    db: Option<&AnalyzerDb>,
    caller: Option<FuncId>,
    suppress_container_taint: bool,
) {
    if let FlowEvent::Assign {
        target,
        source_name,
        source_call,
        source_call_args,
        source_names,
        span,
        ..
    } = event
    {
        if target.is_empty() {
            return;
        }
        if suppress_container_taint {
            return;
        }
        let assignment_rhs = assignment_rhs_text(db, *span);
        if assignment_lhs_projects_collapsed_target(db, *span, target) {
            let rhs_tainted = assignment_rhs
                .as_deref()
                .is_some_and(|rhs| assignment_rhs_is_tainted(rhs, state))
                || source_name
                    .as_deref()
                    .is_some_and(|src| arg_text_is_tainted(src, state))
                || source_call.as_deref().is_some_and(|callee| {
                    source_call_rhs_is_tainted(callee, source_call_args, source_names, state)
                });
            if rhs_tainted {
                insert_descendant_target_taint(state, target);
            }
            return;
        }
        if source_call.is_none() {
            let field_values = assignment_rhs
                .as_deref()
                .map(|rhs| named_field_initializer_values_for_target(target, rhs))
                .unwrap_or_default();
            if !field_values.is_empty() {
                remove_target_and_descendant_taint(state, target);
                for field_value in field_values {
                    if assignment_rhs_is_tainted(&field_value, state)
                        || actual_has_descendant_taint(&field_value, state)
                    {
                        insert_value_target_taint(state, target);
                        if actual_has_descendant_taint(&field_value, state) {
                            insert_descendant_target_taint(state, target);
                        }
                    }
                    if state.contains(&normalise_target_text(target)) {
                        break;
                    }
                }
                return;
            }
        }
        let non_call_rhs_tainted = source_call.is_none()
            && assignment_rhs
                .as_deref()
                .is_some_and(|rhs| assignment_rhs_is_tainted(rhs, state));
        if let Some(rhs) = assignment_rhs.as_ref() {
            if assignment_span_lhs_matches_target(db, *span, target)
                && !named_field_initializers(rhs).is_empty()
            {
                let field_updates = named_field_initializers(rhs);
                let mut changed = apply_named_field_arg_taint(target, &[rhs.clone()], state);
                if named_field_update_copies_tainted_base(
                    source_names,
                    &field_updates,
                    *span,
                    db,
                    caller,
                    state,
                ) {
                    insert_descendant_target_taint(state, target);
                    changed = true;
                }
                if changed {
                    return;
                }
                remove_target_taint(state, target);
                return;
            }
        }
        if let Some(callee) = source_call.as_deref() {
            if source_call_rhs_is_tainted(callee, source_call_args, source_names, state) {
                insert_value_target_taint(state, target);
                if rhs_has_descendant_shape(source_names) {
                    insert_descendant_target_taint(state, target);
                }
                return;
            }
            if source_names.is_empty() && state.contains(target) {
                return;
            }
        }
        if source_call.is_none() {
            if let Some(field_target) = qualified_lhs_for_synthetic_carrier_target(target, *span, db) {
                let rhs_tainted = source_name
                    .as_deref()
                    .is_some_and(|src| arg_text_is_tainted(src, state))
                    || assignment_source_names_any_tainted(source_names, *span, db, caller, state);
                if rhs_tainted {
                    insert_value_target_taint(state, &field_target);
                    if rhs_has_descendant_shape(source_names) {
                        insert_descendant_target_taint(state, &field_target);
                    }
                } else {
                    remove_target_taint(state, &field_target);
                }
                return;
            }
        }
        // G2: compound-expression RHS operands (concat, ternary,
        // template literal, member access, subscript). If ANY
        // operand is currently tainted, taint the target.
        //
        // Field-sensitivity: when the RHS is a qualified read
        // (`data['other']` produces source_names containing both
        // `data` and `data.other` from the adapter), bare-name
        // operands like `data` should NOT match against
        // qualified seeds in state via the loose
        // base/tail-promotion that `state_qualified_token_matches_text`
        // performs at call-site checks. That promotion is correct
        // for arg passing (passing `obj` propagates carrier
        // taint) but wrong for assignment RHS extraction
        // (`out = data['other']` should not pick up
        // `data.value`'s taint because `data['other']` and
        // `data['value']` are distinct fields). Use the
        // strict comparison that requires explicit qualified
        // matching or direct membership.
        if !source_names.is_empty() {
            if source_call.is_none()
                && assignment_span_is_iteration_binding(db, *span, target)
                && source_names.iter().any(|source| {
                    actual_has_descendant_taint(source, state)
                        || arg_text_has_mapped_descendant_taint(source, state)
                })
            {
                insert_descendant_target_taint(state, target);
                return;
            }
            if assignment_source_names_any_tainted(source_names, *span, db, caller, state)
                || non_call_rhs_tainted
            {
                insert_value_target_taint(state, target);
                if rhs_has_descendant_shape(source_names) {
                    insert_descendant_target_taint(state, target);
                }
                return;
            }
        }
        let qualified_bases = synthetic_qualified_source_bases(source_names, *span, db);
        match source_name.as_deref() {
            Some(src)
                if assignment_source_name_is_value_tainted(src, &qualified_bases, db, caller, state) =>
            {
                insert_value_target_taint(state, target);
            }
            Some(src)
                if source_call.is_none()
                    && !qualified_bases.contains(&canonical_bare_name(src))
                    && copy_assignment_descendant_taint(state, target, src) => {}
            _ if non_call_rhs_tainted => {
                insert_value_target_taint(state, target);
                if rhs_has_descendant_shape(source_names) {
                    insert_descendant_target_taint(state, target);
                }
            }
            Some(_) | None => {
                // Semantic overwrite: if the RHS did not expose
                // a tainted source_name/source_names/source_call
                // path above, the previous value no longer
                // reaches this target.
                remove_target_taint(state, target);
            }
        }
    }
}

fn qualified_lhs_for_synthetic_carrier_target(
    target: &str,
    span: Span,
    db: Option<&AnalyzerDb>,
) -> Option<String> {
    let target = normalise_target_text(target);
    if target.is_empty() || text_looks_qualified(&target) {
        return None;
    }
    let (lhs, _) = assignment_text_parts(db?, span)?;
    let lhs = normalise_qualified_text(lhs.trim());
    if lhs == target {
        return None;
    }
    lhs.strip_prefix(target.as_str())
        .is_some_and(|rest| rest.starts_with('.'))
        .then_some(lhs)
}

fn assignment_span_lhs_matches_target(db: Option<&AnalyzerDb>, span: Span, target: &str) -> bool {
    let target = normalise_target_text(target);
    if target.is_empty() {
        return false;
    }
    let Some(db) = db else {
        return false;
    };
    assignment_text_parts(db, span)
        .map(|(lhs, _)| normalise_qualified_text(lhs.trim()) == target)
        .unwrap_or(false)
}

fn assignment_lhs_projects_collapsed_target(db: Option<&AnalyzerDb>, span: Span, target: &str) -> bool {
    let target = normalise_target_text(target);
    if target.is_empty() || text_looks_qualified(&target) {
        return false;
    }
    let Some((lhs, _)) = db.and_then(|db| assignment_text_parts(db, span)) else {
        return false;
    };
    let lhs = lhs.trim();
    if lhs.is_empty() {
        return false;
    }
    if normalise_qualified_text(lhs) == target {
        return false;
    }
    lhs_projection_base_matches_target(lhs, &target)
}

fn lhs_projection_base_matches_target(lhs: &str, target: &str) -> bool {
    let lhs = lhs.trim().trim_start_matches(&['*', '&'][..]).trim();
    let target = target.trim();
    if lhs.is_empty() || target.is_empty() || lhs == target {
        return false;
    }
    let Some(rest) = lhs.strip_prefix(target) else {
        return false;
    };
    matches!(
        rest.trim_start().chars().next(),
        Some('[' | '.' | '-' | ':' | '?')
    )
}

fn assignment_rhs_text(db: Option<&AnalyzerDb>, span: Span) -> Option<String> {
    let (_, rhs) = assignment_text_parts(db?, span)?;
    let rhs = rhs
        .trim()
        .trim_end_matches(';')
        .trim_end_matches('.')
        .trim()
        .to_string();
    (!rhs.is_empty()).then_some(rhs)
}

fn assignment_span_is_iteration_binding(db: Option<&AnalyzerDb>, span: Span, target: &str) -> bool {
    let Some(db) = db else {
        return false;
    };
    let target = target.trim();
    if target.is_empty() {
        return false;
    }
    let Ok(snapshot) = db.vfs().snapshot(span.file) else {
        return false;
    };
    let text = snapshot.text.as_ref();
    let start = usize::try_from(span.start).ok().unwrap_or(0).min(text.len());
    let end = usize::try_from(span.end)
        .ok()
        .unwrap_or(text.len())
        .min(text.len());
    if start >= end || !text.is_char_boundary(start) || !text.is_char_boundary(end) {
        return false;
    }
    let statement = &text[start..end];
    let lowered = statement.trim_start();
    if let Some((binding, _iterable)) = lowered.split_once(" range ") {
        return identifier_tokens_outside_strings(binding)
            .iter()
            .any(|token| token == target);
    }
    if !(lowered.starts_with("for ")
        || lowered.starts_with("for(")
        || lowered.starts_with("async for ")
        || lowered.starts_with("foreach ")
        || lowered.starts_with("foreach("))
    {
        return false;
    }
    let Some((binding, _iterable)) = lowered
        .split_once(" in ")
        .or_else(|| lowered.split_once(" of "))
        .or_else(|| lowered.split_once(" range "))
    else {
        return false;
    };
    identifier_tokens_outside_strings(binding)
        .iter()
        .any(|token| token == target)
}

fn assignment_text_parts(db: &AnalyzerDb, span: Span) -> Option<(String, String)> {
    let snapshot = db.vfs().snapshot(span.file).ok()?;
    let text = snapshot.text.as_ref();
    let start = usize::try_from(span.start).ok()?.min(text.len());
    let end = usize::try_from(span.end).ok()?.min(text.len());
    if start >= end || !text.is_char_boundary(start) || !text.is_char_boundary(end) {
        return None;
    }
    let statement = &text[start..end];
    let (idx, separator_len) = find_top_level_assignment_separator(statement)?;
    Some((
        statement[..idx].to_string(),
        statement[idx + separator_len..].to_string(),
    ))
}

fn find_top_level_assignment_separator(text: &str) -> Option<(usize, usize)> {
    let mut quote: Option<char> = None;
    let mut escaped = false;
    let mut depth = 0usize;
    let mut iter = text.char_indices().peekable();
    while let Some((idx, ch)) = iter.next() {
        if let Some(q) = quote {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == q {
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
                let prev = text[..idx].chars().next_back();
                let next = iter.peek().map(|(_, next)| *next);
                if matches!(next, Some('>')) {
                    return Some((idx, 2));
                }
                if matches!(prev, Some('=' | '!' | '<' | '>' | ':')) || matches!(next, Some('=')) {
                    continue;
                }
                return Some((idx, 1));
            }
            _ => {}
        }
    }
    None
}

pub(super) fn insert_target_taint(state: &mut TokenSet, target: &str) {
    let target = normalise_target_text(target);
    if target.is_empty() {
        return;
    }
    state.insert(target.clone());
    // Sigil-strip alias (`$x` ↔ `x`, `@v` ↔ `v`, `%h` ↔ `h`) for
    // languages like Perl/Ruby/PHP where the same identity has
    // distinct surface forms. This is identity normalisation, not
    // a base promotion.
    let bare = target.trim_start_matches(&['$', '@', '%'][..]);
    if bare != target && !bare.is_empty() {
        state.insert(bare.to_string());
    }
    // Per-field taint granularity (concept 8): only the explicit
    // target enters state. Don't promote the bare carrier
    // (`obj.value = tainted` must NOT mark `obj` as wholesale
    // tainted), otherwise reads of unrelated fields like
    // `obj.other` would over-report. The cross-call carrier
    // propagation that DOES need to fire (`process(obj)` should
    // see a tainted argument when any field of `obj` was written)
    // is handled at read time via
    // `state_qualified_token_matches_text`, which iterates seeds
    // and matches a bare-name read against any qualified seed
    // sharing that base. See `arg_text_is_tainted`.
}

pub(super) fn insert_value_target_taint(state: &mut TokenSet, target: &str) {
    insert_target_taint(state, target);
    let target = normalise_target_text(target);
    if target.is_empty() || text_looks_qualified(&target) {
        return;
    }
    state.insert(value_marker(&target));
}

pub(super) fn insert_descendant_target_taint(state: &mut TokenSet, target: &str) {
    let target = normalise_target_text(target);
    if target.is_empty() || text_looks_qualified(&target) || target.ends_with(".*") {
        return;
    }
    state.insert(format!("{target}.*"));
    let bare = target.trim_start_matches(&['$', '@', '%'][..]);
    if bare != target && !bare.is_empty() {
        state.insert(format!("{bare}.*"));
    }
}

pub(super) fn bind_param_taint(
    state: &mut TokenSet,
    param_name: &str,
    actual_text: &str,
    caller_state: &TokenSet,
) {
    let actual = normalise_target_text(actual_text);
    let direct_value = !actual.is_empty()
        && (caller_state.contains(&actual)
            || caller_state.contains(actual_text.trim())
            || actual_has_value_taint(actual_text, caller_state));
    if direct_value || actual.is_empty() {
        insert_value_target_taint(state, param_name);
    }
    let mut mapped_descendant = false;
    if !actual.is_empty() {
        mapped_descendant = bind_matching_descendant_taint(state, param_name, &actual, caller_state);
    }
    if !direct_value && !mapped_descendant && arg_text_is_tainted(actual_text, caller_state) {
        insert_value_target_taint(state, param_name);
    }
    if actual_has_descendant_taint(actual_text, caller_state) {
        insert_descendant_target_taint(state, param_name);
    }
}

fn bind_matching_descendant_taint(
    state: &mut TokenSet,
    param_name: &str,
    actual_base: &str,
    caller_state: &TokenSet,
) -> bool {
    let param = normalise_target_text(param_name);
    if param.is_empty() {
        return false;
    }
    let mut matched = false;
    for actual_key in access_alias_keys(actual_base) {
        let wildcard = format!("{actual_key}.*");
        for seed in caller_state {
            let seed = normalise_qualified_text(seed);
            if seed == wildcard {
                insert_descendant_target_taint(state, &param);
                matched = true;
                continue;
            }
            let Some(tail) = seed.strip_prefix(&actual_key) else {
                continue;
            };
            if !tail.starts_with('.') {
                continue;
            }
            let mapped = format!("{param}{tail}");
            insert_target_taint(state, &mapped);
            matched = true;
        }
    }
    matched
}

fn arg_text_has_mapped_descendant_taint(actual_text: &str, caller_state: &TokenSet) -> bool {
    let actual = normalise_target_text(actual_text);
    if actual.is_empty() || !is_addressable_access_text(&actual) {
        return false;
    }
    access_alias_keys(&actual).iter().any(|actual_key| {
        let wildcard = format!("{actual_key}.*");
        caller_state.iter().any(|seed| {
            let seed = normalise_qualified_text(seed);
            seed == wildcard
                || seed
                    .strip_prefix(actual_key.as_str())
                    .is_some_and(|tail| tail.starts_with('.'))
        })
    })
}

fn mapped_descendant_display(actual_text: &str, caller_state: &TokenSet) -> Option<String> {
    let actual = normalise_target_text(actual_text);
    if actual.is_empty() || !is_addressable_access_text(&actual) {
        return None;
    }
    let actual_keys = access_alias_keys(&actual);
    let mut fields = Vec::new();
    for seed in caller_state {
        let seed = normalise_qualified_text(seed);
        if seed.ends_with(".*") {
            continue;
        }
        for actual_key in &actual_keys {
            let Some(tail) = seed.strip_prefix(actual_key.as_str()) else {
                continue;
            };
            if !tail.starts_with('.') {
                continue;
            }
            let mapped = format!("{actual}{tail}");
            if !fields.iter().any(|existing| existing == &mapped) {
                fields.push(mapped);
            }
        }
    }
    fields.sort();
    fields.into_iter().next()
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
    for actual_key in access_alias_keys(&actual) {
        let wildcard = format!("{actual_key}.*");
        for seed in state.clone() {
            let seed = normalise_qualified_text(&seed);
            if seed == wildcard {
                let before = state.len();
                insert_descendant_target_taint(state, &target);
                changed |= state.len() != before;
                continue;
            }
            let Some(tail) = seed.strip_prefix(actual_key.as_str()) else {
                continue;
            };
            if !tail.starts_with('.') {
                continue;
            }
            let before = state.len();
            insert_target_taint(state, &format!("{target}{tail}"));
            changed |= state.len() != before;
        }
    }
    changed
}

fn is_bare_identifier_text(text: &str) -> bool {
    let text = text.trim();
    !text.is_empty() && text.chars().all(is_identifier_byteish)
}

fn is_addressable_access_text(text: &str) -> bool {
    let text = text.trim();
    !text.is_empty()
        && !text.starts_with('.')
        && !text.ends_with('.')
        && text.chars().all(|ch| ch == '.' || is_identifier_byteish(ch))
}

pub(super) fn value_marker(name: &str) -> String {
    format!("{name}#__value")
}

fn actual_has_value_taint(actual_text: &str, state: &TokenSet) -> bool {
    let actual = normalise_target_text(actual_text);
    !actual.is_empty() && state.contains(&value_marker(&actual))
}

fn actual_has_descendant_taint(actual_text: &str, state: &TokenSet) -> bool {
    let actual = normalise_qualified_text(actual_text.trim());
    !actual.is_empty() && qualified_wildcard_seed_matches(&actual, state)
}

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

pub(super) fn normalise_target_text(target: &str) -> String {
    use bonsai_common::REFERENCE_SIGILS;
    normalise_qualified_text(target)
        .trim_start_matches(REFERENCE_SIGILS)
        .trim()
        .to_string()
}

fn qualified_source_bases(source_names: &[String]) -> AHashSet<String> {
    let mut bases = AHashSet::new();
    for source in source_names {
        for base in qualified_access_bases(source) {
            bases.insert(base);
        }
    }
    bases
}

fn synthetic_qualified_source_bases(
    source_names: &[String],
    span: Span,
    db: Option<&AnalyzerDb>,
) -> AHashSet<String> {
    let mut bases = AHashSet::new();
    for base in qualified_source_bases(source_names) {
        let has_standalone = db.is_some_and(|db| source_span_has_standalone_identifier(db, span, &base));
        if !has_standalone {
            bases.insert(base);
        }
    }
    if let Some(db) = db {
        if let Some(text) = source_span_text(db, span) {
            for base in qualified_access_bases(&text) {
                if !identifier_value_occurs(&text, &base) {
                    bases.insert(base);
                }
            }
            for prefix in qualified_access_prefixes(&text) {
                if !identifier_value_occurs(&text, &prefix) {
                    bases.insert(prefix);
                }
            }
        }
    }
    bases
}

fn qualified_access_prefixes(text: &str) -> Vec<String> {
    let mut prefixes = Vec::new();
    for access in qualified_accesses(text) {
        let parts: Vec<&str> = access.split('.').filter(|part| !part.is_empty()).collect();
        if parts.len() < 3 {
            continue;
        }
        for end in 1..parts.len() {
            let prefix = parts[..end].join(".");
            if !prefixes.iter().any(|existing| existing == &prefix) {
                prefixes.push(prefix);
            }
        }
    }
    prefixes
}

fn source_span_text(db: &AnalyzerDb, span: Span) -> Option<String> {
    let snapshot = db.vfs().snapshot(span.file).ok()?;
    let text = snapshot.text.as_ref();
    let start = usize::try_from(span.start).ok()?.min(text.len());
    let end = usize::try_from(span.end).ok()?.min(text.len());
    if start >= end || !text.is_char_boundary(start) || !text.is_char_boundary(end) {
        return None;
    }
    Some(text[start..end].to_string())
}

fn source_span_has_standalone_identifier(db: &AnalyzerDb, span: Span, ident: &str) -> bool {
    let ident = ident.trim();
    if ident.is_empty() {
        return false;
    }
    source_span_text(db, span).is_some_and(|haystack| identifier_value_occurs(&haystack, ident))
}

pub(super) fn identifier_value_occurs(haystack: &str, ident: &str) -> bool {
    let trimmed = ident.trim_start_matches(bonsai_common::IDENTIFIER_SIGILS);
    let mut needles = vec![ident.to_string()];
    if trimmed != ident && !trimmed.is_empty() {
        needles.push(trimmed.to_string());
    }
    if !trimmed.is_empty() {
        for sigil in bonsai_common::IDENTIFIER_SIGILS {
            let with_sigil = format!("{sigil}{trimmed}");
            if !needles.iter().any(|needle| needle == &with_sigil) {
                needles.push(with_sigil);
            }
        }
    }
    needles
        .iter()
        .any(|needle| identifier_value_occurs_exact(haystack, needle))
}

fn identifier_value_occurs_exact(haystack: &str, needle: &str) -> bool {
    if needle.is_empty() {
        return false;
    }
    let mut search_from = 0;
    while let Some(relative) = haystack[search_from..].find(needle) {
        let start = search_from + relative;
        let end = start + needle.len();
        if identifier_value_occurrence_at(haystack, start, end) {
            return true;
        }
        search_from = end;
    }
    false
}

fn identifier_value_occurrence_at(haystack: &str, start: usize, end: usize) -> bool {
    let prev = haystack[..start].chars().next_back();
    if prev.is_some_and(|ch| is_identifier_byteish(ch) || matches!(ch, '.' | '>')) {
        return false;
    }
    let next = haystack[end..].chars().next();
    if next.is_some_and(is_identifier_byteish) {
        return false;
    }
    if matches!(next, Some('.' | '[' | ':')) {
        return false;
    }
    if matches!(next, Some('-')) && haystack[end..].starts_with("->") {
        return false;
    }
    if matches!(next, Some('?')) && haystack[end..].starts_with("?.") {
        return false;
    }
    true
}

fn is_identifier_byteish(ch: char) -> bool {
    ch == '_' || ch == '$' || ch == '@' || ch == '%' || ch.is_ascii_alphanumeric()
}

fn canonical_bare_name(text: &str) -> String {
    normalise_qualified_text(text)
        .trim_start_matches(&['$', '@', '%'][..])
        .trim()
        .to_string()
}

/// Mirror of [`insert_target_taint`] that REMOVES the same set of
/// canonicalized aliases. When a clean reassignment removes
/// `$x` from state, the bare-form `x` (which `insert_target_taint`
/// also added) must come out too — otherwise `x` lingers and
/// `arg_text_is_tainted("$x", state)` re-reports tainted via the
/// `identifier_tokens_outside_strings` fallback. Branch-merge
/// precision (Task #285) breaks at the merge without this.
fn remove_target_taint(state: &mut TokenSet, target: &str) {
    let target = normalise_target_text(target);
    if target.is_empty() {
        return;
    }
    state.remove(&target);
    state.remove(&value_marker(&target));
    state.remove(&format!("{target}.*"));
    let bare = target.trim_start_matches(&['$', '@', '%'][..]);
    if bare != target && !bare.is_empty() {
        state.remove(bare);
        state.remove(&value_marker(bare));
        state.remove(&format!("{bare}.*"));
    }
}

fn remove_target_and_descendant_taint(state: &mut TokenSet, target: &str) {
    let target = normalise_target_text(target);
    if target.is_empty() {
        return;
    }
    remove_target_taint(state, &target);
    let bare = target.trim_start_matches(&['$', '@', '%'][..]).to_string();
    let prefixes = if bare != target && !bare.is_empty() {
        vec![format!("{target}."), format!("{bare}.")]
    } else {
        vec![format!("{target}.")]
    };
    state.retain(|seed| {
        let normalised = normalise_qualified_text(seed);
        !prefixes
            .iter()
            .any(|prefix| seed.starts_with(prefix) || normalised.starts_with(prefix))
    });
}

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
        let tail = normalised.rsplit('.').next().unwrap_or_default();
        text == base || text == tail
    })
}

fn tainted_receiver_access(text: &str, state: &TokenSet) -> bool {
    if !text_looks_qualified(text) {
        return false;
    }
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

fn receiver_method_projection_is_tainted(text: &str, state: &TokenSet) -> bool {
    if receiver_method_projection_in_text_is_tainted(text, state) {
        return true;
    }
    let normalised = normalise_qualified_text(&text.replace("::", "."));
    normalised != text && receiver_method_projection_in_text_is_tainted(&normalised, state)
}

fn receiver_method_projection_in_text_is_tainted(text: &str, state: &TokenSet) -> bool {
    for open_paren in text.match_indices('(').map(|(idx, _)| idx) {
        let before_call = text[..open_paren].trim_end();
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

pub(super) fn qualified_wildcard_seed_matches(normalised_text: &str, state: &TokenSet) -> bool {
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

fn const_value_of_arg(text: &str, const_bindings: &AHashMap<String, ConstValue>) -> Option<ConstValue> {
    let trimmed = trim_outer_parens(text.trim());
    if trimmed.is_empty() || is_quoted_literal(trimmed) {
        return None;
    }
    let bare = canonical_bare_name(trimmed);
    const_bindings
        .get(trimmed)
        .copied()
        .or_else(|| const_bindings.get(bare.as_str()).copied())
        .or_else(|| parse_const_literal(trimmed))
}

fn parse_const_literal(text: &str) -> Option<ConstValue> {
    let lower = text.trim().to_ascii_lowercase();
    match lower.as_str() {
        "true" => Some(ConstValue::Bool(true)),
        "false" => Some(ConstValue::Bool(false)),
        _ => lower.parse::<i64>().ok().map(ConstValue::Int),
    }
}

fn evaluate_branch_condition(
    condition: Option<&str>,
    const_bindings: &AHashMap<String, ConstValue>,
) -> Option<bool> {
    let condition = trim_outer_parens(condition?.trim());
    if condition.is_empty() {
        return None;
    }
    if let Some(rest) = condition.strip_prefix('!') {
        if !rest.starts_with('=') {
            return const_value_of_arg(rest, const_bindings).map(|value| !value.truthy());
        }
    }
    if let Some(rest) = condition.strip_prefix("not ") {
        return const_value_of_arg(rest, const_bindings).map(|value| !value.truthy());
    }
    if let Some(rest) = condition
        .strip_prefix("not(")
        .and_then(|rest| rest.strip_suffix(')'))
    {
        return const_value_of_arg(rest, const_bindings).map(|value| !value.truthy());
    }

    for op in ["!==", "===", "!=", "=="] {
        if let Some((left, right)) = condition.split_once(op) {
            let left = const_value_of_arg(left, const_bindings)?;
            let right = const_value_of_arg(right, const_bindings)?;
            let equal = const_values_equal(left, right);
            return Some(matches!(op, "==" | "===") == equal);
        }
    }

    const_value_of_arg(condition, const_bindings).map(ConstValue::truthy)
}

fn const_values_equal(left: ConstValue, right: ConstValue) -> bool {
    match (left, right) {
        (ConstValue::Bool(a), ConstValue::Bool(b)) => a == b,
        (ConstValue::Int(a), ConstValue::Int(b)) => a == b,
        (a, b) => a.truthy() == b.truthy(),
    }
}

fn trim_outer_parens(mut text: &str) -> &str {
    loop {
        let trimmed = text.trim();
        if !(trimmed.starts_with('(') && trimmed.ends_with(')')) {
            return trimmed;
        }
        let mut depth = 0i32;
        let mut balanced_outer = true;
        for (idx, ch) in trimmed.char_indices() {
            match ch {
                '(' => depth += 1,
                ')' => {
                    depth -= 1;
                    if depth == 0 && idx + ch.len_utf8() < trimmed.len() {
                        balanced_outer = false;
                        break;
                    }
                }
                _ => {}
            }
            if depth < 0 {
                balanced_outer = false;
                break;
            }
        }
        if !balanced_outer || depth != 0 {
            return trimmed;
        }
        text = &trimmed[1..trimmed.len() - 1];
    }
}

fn identifier_tokens_outside_strings(text: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut quote: Option<char> = None;
    let mut escaped = false;
    for c in text.chars() {
        if let Some(q) = quote {
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
// G1 — Return-value taint via function summaries.
//
// A function summary records which PARAMETER INDICES, when tainted on
// entry, still contribute to the function's return value at every exit
// point. For `def transform(x): return x.upper()` the summary is
// `{ returns_taint_of: {0} }` (param 0 transits to the return). For
// `def sanitize(x): return x.replace("'", "''")` it's also `{0}` because
// sanitizer classification does not alter propagation. For
// `def constant(): return 42` it's `{}` (nothing transits to the return).
//
// The current implementation lives in `inter/summary_impl.rs`. It uses
// adapter-supplied `Return.value_name` when available, otherwise explicit
// return text / terminal tail-expression evidence, and tracks direct,
// descendant, container, access-path, and parameter-side-effect transit
// separately. Public callers clamp precision to exact/narrowed semantic
// evidence; unresolved or diagnostic-only edges are not promoted into
// returned summary facts.
// ---------------------------------------------------------------------------

// Public summary types live in `inter/summary.rs`; re-exported below.

// `function_summary` (the public accessor) lives in `inter/summary.rs`
// alongside its return type definitions.

#[cfg(test)]
mod tests;
