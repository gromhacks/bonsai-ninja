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
//! - **Virtual edges carry precision:** a call that resolves to N
//!   candidates propagates to all N, and the result's overall
//!   [`Precision`] degrades to `OverApproximate`. Narrowed / Exact
//!   chains keep their precision.
//! - **Recursion-safe:** `(func, taint-set)` pairs are memoized, so
//!   cycles terminate once the taint set stabilises.
//! - **Resumable:** the worklist can be sliced into bounded chunks
//!   ([`InterTaintConfig::budget`]) and resumed to a fixed point by
//!   callers that need complete flow evidence.
//!
//! ## Remaining approximations
//!
//! - Return-value taint is summary-driven and conservative. When an
//!   adapter emits `Assign.source_call`, the pass propagates through
//!   callee return summaries; imprecise return shapes may still
//!   over-approximate rather than prove a value clean.
//! - Side-effectful unknown calls are modeled for common pointer/out
//!   argument shapes, but full mutation summaries (`foo(&mut x)`
//!   precisely dirtying or cleaning `x`) remain approximate.
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
pub use summary::{function_summary, FunctionSummary, ParamSideEffect, ReturnAccessPath};

pub(super) use summary_impl::compute_function_summary;
use summary_impl::{access_alias_keys, implicit_receiver_return_is_tainted, receiver_state_names_for_decl};

use ahash::{AHashMap, AHashSet};
use bonsai_callgraph::EdgeKind;
use bonsai_common::{callable_reference_variants, FileId, FuncId, Precision, Span, SymbolId};
use bonsai_db::AnalyzerDb;
use bonsai_index::GlobalIndex;
use bonsai_lang_api::ModulePath;
use bonsai_lang_api::{AliasTarget, CallArg, Decl, DeclKind, FlowEvent, TypeAliasBinding};
use bonsai_resolve::{
    alias_map_for_file, resolve_callable_with_context, resolve_class, short_tail, visibility_allows,
    ResolveContext,
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
#[derive(Clone, Debug, Default)]
pub struct InterTaintCaches {
    aliases_by_file: AHashMap<FileId, AHashMap<String, String>>,
    alias_targets_by_func: AHashMap<FuncId, AHashMap<String, AliasTarget>>,
    local_bindings_by_func: AHashMap<FuncId, AHashMap<String, FuncId>>,
    summaries_by_func: AHashMap<FuncId, FunctionSummary>,
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
            callback_invocation_methods: AHashSet::default(),
            receiver_state_propagations: Vec::new(),
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
    let mut caches = InterTaintCaches::default();
    interprocedural_taint_with_caches(entry_func, entry_sources, config, db, &mut caches)
}

/// Run interprocedural taint while reusing resolver caches across
/// repeated runs in the same workspace.
#[must_use]
pub fn interprocedural_taint_with_caches(
    entry_func: FuncId,
    entry_sources: &TokenSet,
    config: &InterTaintConfig,
    db: &AnalyzerDb,
    caches: &mut InterTaintCaches,
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

/// Continue a previously saturated interprocedural run.
#[must_use]
pub fn resume_interprocedural_taint_with_caches(
    mut previous: InterTaintResult,
    config: &InterTaintConfig,
    db: &AnalyzerDb,
    caches: &mut InterTaintCaches,
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
    caches: &mut InterTaintCaches,
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
    caches: &mut InterTaintCaches,
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
        let aliases = caches
            .aliases_by_file
            .entry(caller_file)
            .or_insert_with(|| alias_map_for_file(&db.imports_for(caller_file)))
            .clone();
        let alias_targets = caches
            .alias_targets_by_func
            .entry(func)
            .or_insert_with(|| alias_targets_for_decl(&db.imports_for(caller_file), &decl))
            .clone();
        let mut local_bindings = caches
            .local_bindings_by_func
            .entry(func)
            .or_insert_with(|| {
                bonsai_callgraph::collect_local_callable_bindings_with_aliases(
                    &decl.flow_events,
                    &global,
                    &decl,
                    &alias_targets,
                )
            })
            .clone();
        // Layer in dynamic callback-param bindings from the call
        // site that put us on the worklist. These take precedence
        // over the static (assignment-only) local_bindings since
        // the parameter shadows any outer alias of the same name.
        for (param, callee) in &dyn_bindings {
            local_bindings.insert(param.clone(), *callee);
        }

        let mut state = seed.clone();
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
        };
        propagate_taint_through_events(
            &decl.flow_events,
            &mut state,
            &mut ctx,
            &mut caches.summaries_by_func,
        );

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
}

fn propagate_taint_through_events(
    events: &[FlowEvent],
    state: &mut TokenSet,
    ctx: &mut PropagationCtx<'_>,
    summary_cache: &mut AHashMap<FuncId, FunctionSummary>,
) {
    for (event_index, event) in events.iter().enumerate() {
        let adjacent_source_call_args = adjacent_call_args_for_assignment(events, event_index);
        let split_call_assignment = split_call_assignment_event(events, event_index);
        let return_tainted_assignment = if let Some(synthetic) = split_call_assignment.as_ref() {
            apply_return_taint(
                synthetic,
                &[],
                state,
                ctx.config,
                ctx.db,
                ctx.aliases,
                ctx.alias_targets,
                ctx.local_bindings,
                ctx.caller,
                summary_cache,
            )
        } else {
            apply_return_taint(
                event,
                &adjacent_source_call_args,
                state,
                ctx.config,
                ctx.db,
                ctx.aliases,
                ctx.alias_targets,
                ctx.local_bindings,
                ctx.caller,
                summary_cache,
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
            } => {
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
            if split_call_assignment.as_ref().is_some_and(|synthetic| {
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
            ) {
                continue;
            }
            apply_event_transfer(event, state, ctx.config, Some(ctx.db), Some(ctx.caller));
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

fn adjacent_call_args_for_assignment(events: &[FlowEvent], event_index: usize) -> Vec<String> {
    let Some(FlowEvent::Assign {
        source_call: Some(source_call),
        source_call_args,
        span: assign_span,
        ..
    }) = events.get(event_index)
    else {
        return Vec::new();
    };
    if !source_call_args.is_empty() {
        return Vec::new();
    }

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
                    && !args.is_empty() =>
            {
                Some(args.iter().map(|arg| arg.value_text.clone()).collect())
            }
            _ => None,
        })
        .unwrap_or_default()
}

fn split_call_assignment_event(events: &[FlowEvent], event_index: usize) -> Option<FlowEvent> {
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
    if !source_call_args.is_empty() {
        return None;
    }

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
            && call_matches_assignment(name))
        .then(|| FlowEvent::Assign {
            span: *assign_span,
            target: target.clone(),
            source_name: None,
            source_call: Some(name.to_string()),
            source_call_args: args.iter().map(|arg| arg.value_text.clone()).collect(),
            source_names: source_names.clone(),
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
    summary_cache: &mut AHashMap<FuncId, FunctionSummary>,
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
    let push_if_tainted = |args: &mut Vec<TaintedArgAtCall>, value: &str| {
        if value.is_empty() || !arg_text_is_tainted(value, state) {
            return;
        }
        push_tainted_arg(args, value);
    };
    if let Some(value) = source_name {
        push_if_tainted(&mut tainted_args, value);
    }
    if let Some(value) = source_call {
        if source_call_rhs_is_tainted(value, source_call_args, source_names, state) {
            push_tainted_arg(&mut tainted_args, value);
        }
    }
    for value in source_call_args {
        push_if_tainted(&mut tainted_args, value);
    }
    let qualified_bases = synthetic_qualified_source_bases(source_names, span, Some(ctx.db));
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

fn propagate_call_event(
    call: CallEventView<'_>,
    state: &mut TokenSet,
    ctx: &mut PropagationCtx<'_>,
    summary_cache: &mut AHashMap<FuncId, FunctionSummary>,
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
    let mut diagnostic_tainted_at_call = tainted_at_call.clone();
    for (idx, arg) in call.args.iter().enumerate() {
        if args_to_propagate_into_callee
            .iter()
            .any(|(existing_idx, _)| *existing_idx == idx)
        {
            continue;
        }
        if arg_text_has_mapped_descendant_taint(&arg.value_text, state) {
            args_to_propagate_into_callee.push((idx, arg.value_text.clone()));
            diagnostic_tainted_at_call.push((idx, arg.value_text.clone()));
        }
    }
    apply_configured_source_output_args(call.name, call.args, ctx.config, state);
    let implicit_receiver = implicit_receiver_from_call_name(call.name, call.call_kind);
    let effective_receiver = call.receiver.or(implicit_receiver.as_deref());
    let tainted_receiver = effective_receiver
        .filter(|receiver| receiver_expr_is_tainted(receiver, state))
        .map(Cow::Borrowed)
        .or_else(|| {
            (call.receiver.is_none() && implicit_receiver.is_some())
                .then(|| caller_implicit_receiver_taint_binding(ctx, state).map(Cow::Owned))
                .flatten()
        });
    if args_to_propagate_into_callee.is_empty() && tainted_receiver.is_none() {
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

    let resolve_scope = CallResolveScope::from_ctx(ctx);
    let candidates = resolve_call_candidates_with_caller_at(
        call.name,
        &resolve_scope,
        call.receiver_types,
        Some(call.span),
    );
    if candidates.is_empty() {
        if !configured_source_output_call(call.name, &tainted_at_call, ctx.config)
            && apply_unresolved_call_side_effects(call.args, &tainted_at_call, state)
        {
            *ctx.precision = ctx.precision.meet(Precision::OverApproximate);
        }
        return;
    }

    let global = ctx.db.global_index();
    for candidate in &candidates {
        let Some(callee_decl) = global.decl_of(SymbolId::new(candidate.func.raw())) else {
            continue;
        };
        let summary = summary_cache.entry(candidate.func).or_insert_with(|| {
            global
                .decl_of(SymbolId::new(candidate.func.raw()))
                .map(compute_function_summary)
                .unwrap_or_default()
        });
        let mut callee_seed = TokenSet::default();
        let mut record_args: Vec<TaintedArg> = Vec::new();
        let mut tainted_param_indices: Vec<(usize, usize, String)> = Vec::new();
        let mut receiver_taint_bound = tainted_receiver.is_none();
        if let (Some(receiver_index), Some(receiver_value)) =
            (callee_decl.receiver_param_index, tainted_receiver.as_deref())
        {
            let Some(param_name) = callee_decl.params.get(receiver_index).cloned() else {
                continue;
            };
            if !param_name.is_empty() {
                bind_param_taint(&mut callee_seed, &param_name, receiver_value, state);
            }
            receiver_taint_bound = true;
            tainted_param_indices.push((receiver_index, 0, receiver_value.to_string()));
            record_args.push(TaintedArg {
                index: receiver_index,
                value_text: receiver_value.to_string(),
                param_name,
            });
        }
        if callee_decl.receiver_param_index.is_none() {
            if let Some(receiver_value) = tainted_receiver.as_deref() {
                let receiver_state_names = receiver_state_names_for_decl(callee_decl);
                for receiver_seed in &receiver_state_names {
                    if !receiver_seed.is_empty() {
                        bind_param_taint(&mut callee_seed, receiver_seed, receiver_value, state);
                    }
                }
                if !receiver_state_names.is_empty() {
                    receiver_taint_bound = true;
                    record_args.push(TaintedArg {
                        index: 0,
                        value_text: receiver_value.to_string(),
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
        if !receiver_taint_bound {
            *ctx.precision = ctx.precision.meet(Precision::OverApproximate);
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
                value_text: value_text.clone(),
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
                Precision::OverApproximate,
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
            *ctx.precision = ctx
                .precision
                .meet(callback.precision)
                .meet(Precision::OverApproximate);
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
    let Some(receiver_value) = ["super", "self", "this", "base"]
        .iter()
        .copied()
        .find(|candidate| {
            receiver_expr_is_tainted(candidate, state) || actual_has_descendant_taint(candidate, state)
        })
    else {
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

fn configured_source_output_call(
    name: &str,
    tainted_at_call: &[(usize, String)],
    config: &InterTaintConfig,
) -> bool {
    let Some(shape) = config
        .source_output_args
        .iter()
        .find(|shape| configured_name_match(&shape.callee, name))
    else {
        return false;
    };
    !tainted_at_call.is_empty()
        && tainted_at_call
            .iter()
        .all(|(idx, _)| shape.output_arg_indices.contains(idx))
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

fn configured_name_match(configured: &str, observed: &str) -> bool {
    let configured = normalise_qualified_text(configured.trim());
    let observed = normalise_qualified_text(observed.trim());
    if configured.is_empty() || observed.is_empty() {
        return false;
    }
    configured == observed || configured == short_tail(&observed)
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
    let mut caches = InterTaintCaches::default();
    call_site_receives_taint_with_caches(func, sink_span, entry_sources, config, db, &mut caches)
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
    caches: &mut InterTaintCaches,
) -> bool {
    let global = db.global_index();
    let Some(decl) = global.decl_of(SymbolId::new(func.raw())).cloned() else {
        return false;
    };
    let Some(file) = global.declaring_file(SymbolId::new(func.raw())) else {
        return false;
    };
    let aliases = caches
        .aliases_by_file
        .entry(file)
        .or_insert_with(|| alias_map_for_file(&db.imports_for(file)))
        .clone();
    let alias_targets = caches
        .alias_targets_by_func
        .entry(func)
        .or_insert_with(|| alias_targets_for_decl(&db.imports_for(file), &decl))
        .clone();
    let local_bindings = caches
        .local_bindings_by_func
        .entry(func)
        .or_insert_with(|| {
            bonsai_callgraph::collect_local_callable_bindings_with_aliases(
                &decl.flow_events,
                &global,
                &decl,
                &alias_targets,
            )
        })
        .clone();
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
        &mut caches.summaries_by_func,
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
    summary_cache: &mut AHashMap<FuncId, FunctionSummary>,
) -> (TokenSet, bool) {
    for (event_index, event) in events.iter().enumerate() {
        let adjacent_source_call_args = adjacent_call_args_for_assignment(events, event_index);
        let split_call_assignment = split_call_assignment_event(events, event_index);
        let return_tainted_assignment = if let Some(synthetic) = split_call_assignment.as_ref() {
            apply_return_taint(
                synthetic,
                &[],
                &mut state,
                ctx.config,
                ctx.db,
                ctx.aliases,
                ctx.alias_targets,
                ctx.local_bindings,
                ctx.caller,
                summary_cache,
            )
        } else {
            apply_return_taint(
                event,
                &adjacent_source_call_args,
                &mut state,
                ctx.config,
                ctx.db,
                ctx.aliases,
                ctx.alias_targets,
                ctx.local_bindings,
                ctx.caller,
                summary_cache,
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
            if split_call_assignment.as_ref().is_some_and(|synthetic| {
                split_call_assignment_consumes_all_tainted_sources(synthetic, &state)
                    && !assignment_event_is_iteration_binding(event, ctx.db)
            }) {
                continue;
            }
            if let FlowEvent::Call { name, args, .. } = event {
                apply_configured_source_output_args(name, args, ctx.config, &mut state);
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
                    let tainted_at_call: Vec<(usize, String)> = args
                        .iter()
                        .enumerate()
                        .filter(|(_, arg)| call_arg_is_tainted(arg, &state))
                        .map(|(idx, arg)| (idx, arg.value_text.clone()))
                        .collect();
                    let _ = apply_unresolved_call_side_effects(args, &tainted_at_call, &mut state);
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
            ) {
                continue;
            }
            apply_event_transfer(event, &mut state, ctx.config, Some(ctx.db), Some(ctx.caller));
        }
    }
    (state, false)
}

fn walk_loop_body_for_sink(
    body: &[FlowEvent],
    state: TokenSet,
    ctx: &SinkWalkCtx<'_>,
    summary_cache: &mut AHashMap<FuncId, FunctionSummary>,
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
    adjacent_source_call_args: &[String],
    state: &mut TokenSet,
    config: &InterTaintConfig,
    db: &AnalyzerDb,
    aliases: &AHashMap<String, String>,
    alias_targets: &AHashMap<String, AliasTarget>,
    local_bindings: &AHashMap<String, FuncId>,
    caller: FuncId,
    summary_cache: &mut AHashMap<FuncId, FunctionSummary>,
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
    let global = db.global_index();
    let mut tainted = false;
    let effective_source_call_args = if source_call_args.is_empty() {
        adjacent_source_call_args
    } else {
        source_call_args.as_slice()
    };
    let resolve_scope = CallResolveScope {
        aliases,
        alias_targets,
        local_bindings,
        db,
        caller,
        config,
    };
    let candidates = resolve_call_candidates_with_caller_at(callee_name, &resolve_scope, &[], Some(*span));
    let tainted_call_arg = effective_source_call_args
        .iter()
        .any(|arg| arg_text_is_tainted(arg, state) || actual_has_descendant_taint(arg, state));
    let has_named_field_args = source_call_args_have_named_fields(effective_source_call_args);
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
        apply_named_field_arg_taint(target, effective_source_call_args, state)
    } else {
        false
    };
    let source_call_rhs_tainted =
        source_call_rhs_is_tainted(callee_name, effective_source_call_args, source_names, state);
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
        insert_value_target_taint(state, target);
        if (source_names_tainted && rhs_has_descendant_shape(source_names))
            || (constructs_container && tainted_call_arg && !has_named_field_args)
        {
            insert_descendant_target_taint(state, target);
        }
        return true;
    }
    for candidate in &candidates {
        let summary = summary_cache.entry(candidate.func).or_insert_with(|| {
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
                .any(|arg| arg_text_is_tainted(arg, state));
        let independent_rhs_operand_tainted = source_names_tainted
            && effective_source_call_args.is_empty()
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
        let value_tainted_transits = source_call_name_is_seeded(callee_name, state)
            || independent_rhs_operand_tainted
            || call_projection_tainted
            || implicit_receiver_return_tainted
            || implicit_receiver_param_return_tainted
            || (summary.returns_taint_of.is_empty()
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
                effective_source_call_args
                    .get(idx)
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
            });
        let access_path_tainted_transits = summary.returns_access_paths.iter().any(|returned| {
            effective_source_call_args
                .get(returned.param)
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
        let descendant_tainted_transits = summary.returns_descendant_taint_of.iter().any(|&idx| {
            effective_source_call_args
                .get(idx)
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
        let container_tainted_transits = summary.returns_container_taint_of.iter().any(|&idx| {
            effective_source_call_args
                .get(idx)
                .map(|arg_text| arg_text_is_tainted(arg_text, state))
                .unwrap_or(false)
                || global
                    .decl_of(SymbolId::new(candidate.func.raw()))
                    .and_then(|decl| decl.receiver_param_index)
                    .is_some_and(|receiver_idx| {
                        receiver_idx == idx
                            && call_receiver_from_name(callee_name)
                                .as_deref()
                                .is_some_and(|receiver| receiver_expr_is_tainted(receiver, state))
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
        if descendant_tainted_transits || container_tainted_transits {
            insert_descendant_target_taint(state, target);
            tainted = true;
        }
        if named_field_tainted && has_named_field_args {
            tainted = true;
        } else if constructs_container && tainted_call_arg {
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

fn source_call_args_have_named_fields(args: &[String]) -> bool {
    args.iter().any(|arg| !named_field_initializers(arg).is_empty())
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
    let ctx =
        ResolveContext::new(caller_decl.span.file, &caller_decl.module_path).with_alias_map(alias_targets);
    if !resolve_class(&global, callee_name, &ctx).is_empty() {
        return true;
    }
    let tail = short_tail(callee_name);
    tail != callee_name && !resolve_class(&global, tail, &ctx).is_empty()
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
    receiver_place_is_tainted(receiver, state) || arg_text_is_tainted(receiver, state)
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
) -> Option<String> {
    if call_kind != bonsai_lang_api::CallKind::Method {
        return None;
    }
    let receiver = call_receiver_from_name(name)?;
    let scoped_call = name.contains("::");
    (matches!(receiver.as_str(), "super" | "parent" | "base")
        || (!scoped_call && matches!(receiver.as_str(), "self" | "this"))
        || (!scoped_call && receiver_projects_implicit_receiver(&format!("{receiver}."))))
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
                }) && receiver_expr_is_tainted(receiver, state)
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
struct ResolvedCallee {
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
    };
    resolve_call_candidates_with_caller_at(name, &scope, &[], None)
}

fn resolve_call_candidates_with_caller_at(
    name: &str,
    scope: &CallResolveScope<'_>,
    receiver_types: &[String],
    call_span: Option<Span>,
) -> Vec<ResolvedCallee> {
    let mut saw_expression_receiver = false;
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
        if let Some(func) = scope
            .local_bindings
            .get(lookup_name)
            .or_else(|| scope.local_bindings.get(tail))
            .copied()
        {
            return vec![ResolvedCallee {
                func,
                kind: EdgeKind::Direct,
                precision: Precision::Narrowed,
            }];
        }
        let exact_targets = resolve_contextual_call_name(lookup_name, scope);
        if !exact_targets.is_empty() {
            return exact_targets;
        }
        if let Some(receiver) = call_receiver_from_name(lookup_name) {
            let targets = if is_super_receiver(&receiver) {
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
                let (kind, precision) = if targets.len() == 1 {
                    (EdgeKind::Direct, Precision::Narrowed)
                } else {
                    (EdgeKind::Virtual, Precision::OverApproximate)
                };
                return targets
                    .into_iter()
                    .map(|func| ResolvedCallee {
                        func,
                        kind,
                        precision,
                    })
                    .collect();
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
                    let (kind, precision) = if candidates.len() == 1 {
                        (EdgeKind::Direct, Precision::Narrowed)
                    } else {
                        (EdgeKind::Virtual, Precision::OverApproximate)
                    };
                    return candidates
                        .into_iter()
                        .map(|func| ResolvedCallee {
                            func,
                            kind,
                            precision,
                        })
                        .collect();
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
                        let (kind, precision) = if candidates.len() == 1 {
                            (EdgeKind::Direct, Precision::Narrowed)
                        } else {
                            (EdgeKind::Virtual, Precision::OverApproximate)
                        };
                        return candidates
                            .into_iter()
                            .map(|func| ResolvedCallee {
                                func,
                                kind,
                                precision,
                            })
                            .collect();
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
                        precision: Precision::OverApproximate,
                    }];
                }
            }
            saw_expression_receiver = true;
            continue;
        }
    }
    if saw_expression_receiver {
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

fn resolve_contextual_call_name(lookup_name: &str, scope: &CallResolveScope<'_>) -> Vec<ResolvedCallee> {
    let global = scope.db.global_index();
    let Some((caller_file, caller_module)) = caller_resolve_context_data(scope.db, scope.caller) else {
        return Vec::new();
    };
    let ctx = ResolveContext::new(caller_file, &caller_module).with_alias_map(scope.alias_targets);
    let candidates = resolve_callable_with_context(&global, lookup_name, &ctx);
    if candidates.is_empty() {
        return Vec::new();
    }
    let (kind, precision) = if candidates.len() == 1 {
        (EdgeKind::Direct, Precision::Narrowed)
    } else {
        (EdgeKind::Virtual, Precision::OverApproximate)
    };
    candidates
        .into_iter()
        .map(|func| ResolvedCallee {
            func,
            kind,
            precision,
        })
        .collect()
}

#[cfg(test)]
fn receiver_allows_name_fallback(
    lookup_name: &str,
    receiver: &str,
    aliases: &AHashMap<String, String>,
    alias_targets: &AHashMap<String, AliasTarget>,
) -> bool {
    let receiver = normalise_qualified_text(receiver);
    let receiver = receiver.trim();
    if receiver.is_empty() {
        return false;
    }
    let head = receiver
        .split(&['.', ':', '\\', '('][..])
        .next()
        .unwrap_or(receiver);
    if receiver
        .chars()
        .any(|ch| matches!(ch, '(' | ')' | '[' | ']' | '{' | '}' | '"' | '\'' | '`') || ch.is_whitespace())
    {
        return false;
    }
    let tail = short_tail(receiver);
    let _ = (lookup_name, tail);
    aliases.contains_key(head) || alias_targets.contains_key(head)
}

fn unique_narrowed_candidate(candidates: &[ResolvedCallee]) -> Option<FuncId> {
    let [candidate] = candidates else {
        return None;
    };
    (candidate.precision == Precision::Narrowed).then_some(candidate.func)
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
        for type_name in receiver_call_return_type_names(
            caller_decl,
            receiver,
            call_span,
            db,
            caller,
            alias_targets,
        ) {
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
    if receiver_projects_implicit_receiver(receiver) {
        if let Some(class_decl) = enclosing_class_for_decl(&global, caller_decl) {
            for base in &class_decl.bases {
                push_unique_string(&mut type_names, base.clone());
            }
        }
    }
    let caller_module = caller_decl.module_path.clone();
    let class_ctx = ResolveContext::new(caller_file, &caller_module).with_alias_map(alias_targets);
    if type_names.is_empty() {
        // Receiver type is unknown — typical for dynamically-typed
        // languages (JS / Python / Ruby / Perl / PHP) where
        // `args.method()` is resolved at runtime via the actual
        // class of `args`. The static analyzer's faithful model is
        // virtual dispatch over every workspace class that defines
        // `method_name`. The caller marks the result
        // `Precision::OverApproximate` (multi-candidate) so
        // downstream consumers can distinguish from
        // statically-narrowed dispatch.
        return collect_virtual_dispatch_candidates(&global, method_name, &class_ctx);
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

/// Virtual dispatch when the receiver type isn't statically known —
/// the language runtime selects a class at call time, so the static
/// analyzer's faithful answer is "every class method by that name
/// the caller's visibility / module context can reach". The caller
/// applies `Precision::OverApproximate` because the dispatch
/// covers more than one candidate; consumers can filter by
/// precision when they want a narrower reading.
fn collect_virtual_dispatch_candidates(
    global: &GlobalIndex,
    method_name: &str,
    ctx: &ResolveContext<'_>,
) -> Vec<FuncId> {
    if method_name.is_empty() {
        return Vec::new();
    }
    let mut out = Vec::new();
    for sym in global.find_by_name(method_name) {
        let Some(decl) = global.decl_of(*sym) else {
            continue;
        };
        if !matches!(
            decl.kind,
            DeclKind::Function | DeclKind::Method | DeclKind::Constructor
        ) {
            continue;
        }
        // Only methods of class-like decls participate in receiver-
        // type dispatch — free functions can't be the target of
        // `obj.method()` at runtime.
        let Some(parent) = decl.parent else {
            continue;
        };
        let Some(parent_decl) = global.decl_of(parent) else {
            continue;
        };
        if !matches!(
            parent_decl.kind,
            DeclKind::Class | DeclKind::Struct | DeclKind::Trait | DeclKind::Interface
        ) {
            continue;
        }
        let Some(decl_file) = global.declaring_file(*sym) else {
            continue;
        };
        if !visibility_allows(decl, decl_file, &decl.module_path, ctx) {
            continue;
        }
        out.push(FuncId::new(decl.symbol.raw()));
    }
    out
}

fn prune_receiver_type_names_for_dispatch(
    type_names: Vec<String>,
    global: &GlobalIndex,
    ctx: &ResolveContext<'_>,
) -> Vec<String> {
    if type_names.len() < 2 {
        return type_names;
    }
    let canonical_types: Vec<String> = type_names
        .iter()
        .map(|name| canonical_dispatch_type_name(name))
        .collect();
    let mut inherited = AHashSet::new();
    for type_name in &type_names {
        for class_sym in resolve_class(global, type_name, ctx) {
            collect_transitive_base_type_names(global, class_sym, ctx, &mut inherited);
        }
    }
    let mut out = Vec::new();
    for (idx, type_name) in type_names.into_iter().enumerate() {
        if inherited.contains(&canonical_types[idx])
            && canonical_types
                .iter()
                .enumerate()
                .any(|(other_idx, other)| other_idx != idx && other != &canonical_types[idx])
        {
            continue;
        }
        push_unique_string(&mut out, type_name);
    }
    out
}

fn collect_transitive_base_type_names(
    global: &GlobalIndex,
    class_sym: SymbolId,
    ctx: &ResolveContext<'_>,
    out: &mut AHashSet<String>,
) {
    let Some(class_decl) = global.decl_of(class_sym) else {
        return;
    };
    for base in &class_decl.bases {
        let canonical = canonical_dispatch_type_name(base);
        if !out.insert(canonical) {
            continue;
        }
        for base_sym in resolve_class(global, base, ctx) {
            collect_transitive_base_type_names(global, base_sym, ctx, out);
        }
    }
}

fn canonical_dispatch_type_name(name: &str) -> String {
    use bonsai_common::ALL_NAME_PUNCTUATION;
    short_tail(name)
        .trim_start_matches(ALL_NAME_PUNCTUATION)
        .trim_end_matches("()")
        .trim()
        .to_string()
}

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

fn receiver_projects_implicit_receiver(receiver: &str) -> bool {
    use bonsai_common::{IMPLICIT_RECEIVER_PREFIXES, SUPER_RECEIVER_TOKENS};
    let receiver = normalise_qualified_text(receiver);
    IMPLICIT_RECEIVER_PREFIXES
        .iter()
        .any(|prefix| receiver.starts_with(*prefix))
        || SUPER_RECEIVER_TOKENS
            .iter()
            .any(|token| receiver.starts_with(&format!("{token}.")))
}

fn is_super_receiver(receiver: &str) -> bool {
    use bonsai_common::{REFERENCE_SIGILS, SUPER_RECEIVER_TOKENS};
    let receiver = receiver.trim().trim_start_matches(REFERENCE_SIGILS);
    let receiver = receiver.strip_suffix("()").unwrap_or(receiver).trim();
    SUPER_RECEIVER_TOKENS.iter().any(|token| *token == receiver)
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
    let ctx = ResolveContext::new(caller_file, &caller_decl.module_path).with_alias_map(alias_targets);
    let mut out = Vec::new();
    let mut seen = AHashSet::new();
    for base in &class_decl.bases {
        for class_sym in resolve_class(&global, base, &ctx) {
            collect_method_candidates_for_class(&global, class_sym, method_name, &ctx, &mut seen, &mut out);
        }
    }
    out
}

fn collect_method_candidates_for_class(
    global: &GlobalIndex,
    class_sym: SymbolId,
    method_name: &str,
    ctx: &ResolveContext<'_>,
    seen: &mut AHashSet<SymbolId>,
    out: &mut Vec<FuncId>,
) {
    let mut seen_classes = AHashSet::new();
    collect_method_candidates_for_class_inner(
        global,
        class_sym,
        method_name,
        ctx,
        seen,
        &mut seen_classes,
        out,
    );
}

fn collect_method_candidates_for_class_inner(
    global: &GlobalIndex,
    class_sym: SymbolId,
    method_name: &str,
    ctx: &ResolveContext<'_>,
    seen_methods: &mut AHashSet<SymbolId>,
    seen_classes: &mut AHashSet<SymbolId>,
    out: &mut Vec<FuncId>,
) {
    if !seen_classes.insert(class_sym) {
        return;
    }
    let Some(class_decl) = global.decl_of(class_sym) else {
        return;
    };
    if !matches!(
        class_decl.kind,
        DeclKind::Class | DeclKind::Struct | DeclKind::Trait | DeclKind::Interface
    ) {
        return;
    }
    let Some(class_file) = global.declaring_file(class_sym) else {
        return;
    };
    let mut matched_local_method = false;
    for decl in global.decls_in(class_file) {
        if decl.name != method_name {
            continue;
        }
        if !matches!(
            decl.kind,
            DeclKind::Function | DeclKind::Method | DeclKind::Constructor
        ) {
            continue;
        }
        let Some(decl_file) = global.declaring_file(decl.symbol) else {
            continue;
        };
        if !visibility_allows(decl, decl_file, &decl.module_path, ctx) {
            continue;
        }
        if decl.parent == Some(class_sym) && seen_methods.insert(decl.symbol) {
            matched_local_method = true;
            out.push(FuncId::new(decl.symbol.raw()));
        }
    }
    if matched_local_method {
        return;
    }
    for base in &class_decl.bases {
        for base_sym in resolve_class(global, base, ctx) {
            collect_method_candidates_for_class_inner(
                global,
                base_sym,
                method_name,
                ctx,
                seen_methods,
                seen_classes,
                out,
            );
        }
    }
}

fn enclosing_class_for_decl<'a>(global: &'a GlobalIndex, decl: &Decl) -> Option<&'a Decl> {
    if let Some(parent) = decl.parent {
        if let Some(parent_decl) = global.decl_of(parent) {
            if matches!(
                parent_decl.kind,
                DeclKind::Class | DeclKind::Struct | DeclKind::Trait | DeclKind::Interface
            ) {
                return Some(parent_decl);
            }
        }
    }
    None
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
    let Some(inner_call) = receiver_inner_call_name(receiver) else {
        return Vec::new();
    };
    let global = db.global_index();
    let Some(caller_file) = global.declaring_file(SymbolId::new(caller.raw())) else {
        return Vec::new();
    };
    let ctx = ResolveContext::new(caller_file, &caller_decl.module_path).with_alias_map(alias_targets);
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
    let mut out = Vec::new();
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

fn callee_without_call_args(callee: &str) -> &str {
    callee.split('(').next().unwrap_or(callee).trim()
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
                } else if static_constructor_return(value_text) {
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
    let mut text = value_text.trim();
    text = text.strip_prefix("return ").unwrap_or(text).trim();
    text = text.strip_prefix("new ").unwrap_or(text).trim();
    let candidate = text
        .split(['(', '{', '[', ' ', '\t', '\r', '\n'])
        .next()
        .unwrap_or(text)
        .trim();
    if candidate.is_empty() || !call_name_looks_type_constructor(candidate) {
        return None;
    }
    if class_like_constructor_call(candidate, db, caller, alias_targets) {
        Some(short_tail(candidate).to_string())
    } else {
        None
    }
}

fn static_constructor_return(value_text: &str) -> bool {
    let mut text = value_text.trim();
    text = text.strip_prefix("return ").unwrap_or(text).trim();
    if text.starts_with("Self(") || text.starts_with("Self {") || text.starts_with("self(") {
        return true;
    }
    matches!(
        text.strip_prefix("new ").map(str::trim),
        Some(rest) if rest.starts_with("static(") || rest.starts_with("self(")
    )
}

fn push_unique_func(out: &mut Vec<FuncId>, func: FuncId) {
    if !out.contains(&func) {
        out.push(func);
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
                    if candidate.is_empty() || !call_name_looks_type_constructor(&candidate) {
                        for token in identifier_tokens_outside_strings(&candidate) {
                            if call_name_looks_type_constructor(&token)
                                && class_like_constructor_call(&token, db, caller, alias_targets)
                            {
                                push_unique_string(out, short_tail(&token).to_string());
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
                if call_name_looks_type_constructor(&candidate)
                    && class_like_constructor_call(&candidate, db, caller, alias_targets)
                {
                    push_unique_string(out, short_tail(&candidate).to_string());
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

pub(super) fn push_unique_string(out: &mut Vec<String>, value: String) {
    if !value.is_empty() && !out.iter().any(|existing| existing == &value) {
        out.push(value);
    }
}

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

fn extend_alias_targets_with_declared_types(
    alias_targets: &mut AHashMap<String, AliasTarget>,
    type_aliases: &[TypeAliasBinding],
) {
    for alias in type_aliases {
        if alias.name.is_empty() || alias.type_name.is_empty() {
            continue;
        }
        alias_targets
            .entry(alias.name.clone())
            .or_insert_with(|| AliasTarget::Type {
                type_name: alias.type_name.clone(),
            });
    }
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
/// caller-file alias map. Produces one or more candidates with
/// edge kind / precision consistent with `add_resolved_call_edges`'s
/// classification (Narrowed+Direct for unique resolution;
/// OverApproximate+Virtual for multi-candidate).
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
        let (kind, precision) = if candidates.len() == 1 {
            (EdgeKind::Direct, Precision::Narrowed)
        } else {
            (EdgeKind::Virtual, Precision::OverApproximate)
        };
        return candidates
            .into_iter()
            .map(|func| ResolvedCallee {
                func,
                kind,
                precision,
            })
            .collect();
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
        let (kind, precision) = if candidates.len() == 1 {
            (EdgeKind::Direct, Precision::Narrowed)
        } else {
            (EdgeKind::Virtual, Precision::OverApproximate)
        };
        return candidates
            .into_iter()
            .map(|func| ResolvedCallee {
                func,
                kind,
                precision,
            })
            .collect();
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
        // Probe the workspace for a decl named `head` that
        // plausibly REPRESENTS A MODULE / NAMESPACE / CLASS
        // container — i.e. a Rust `use foo::{self}` re-export, a
        // C++ `namespace foo`, etc. `find_by_name` is keyed on
        // `qualified_name.unwrap_or(name)` so most adapter decls
        // (which leave `qualified_name=None`) match by bare name;
        // the kind filter is what makes the probe meaningful.
        //
        // Today only `DeclKind::Class` fires in practice — the
        // shared `kit` flattens Rust traits/structs/enums and C++
        // class_specifier all to `Class`, and `mod_item` /
        // `namespace_definition` aren't currently indexed at all
        // (so the workspace-re-export case of Rust `use foo::{self}`
        // where `foo` is a `mod foo;` doesn't register here). The
        // `Module` / `Namespace` arms are reserved for a future
        // kit enrichment that emits those kinds for module-shaped
        // nodes; until then, a workspace `struct foo` IS treated
        // as a non-external head, accepting the Go-style trade-off
        // that `import "fmt"` + `struct fmt` collides on `fmt`.
        let head_is_workspace_symbol = alias_head
            .map(|h| {
                let Some((caller_file, caller_module)) = caller_ctx.as_ref() else {
                    return false;
                };
                let ctx = ResolveContext::new(*caller_file, caller_module).with_alias_map(alias_targets);
                !resolve_class(&global, h, &ctx).is_empty()
            })
            .unwrap_or(false);
        let alias_marks_external =
            (alias_is_self_binding || alias_is_path_style) && !head_is_workspace_symbol;
        if candidates.is_empty() && !alias_marks_external {
            candidates = lookup(alias_tail);
        }
        if candidates.is_empty() && (!alias_is_self_binding || head_is_workspace_symbol) {
            // Skip the rewrite for external-package self-bindings —
            // `{fmt}.{Println}` is byte-identical to the bare
            // `fmt.Println` we already tried at the top of the
            // function. Path-style aliases (e.g. `io/fs`) still try
            // the rewrite because `io/fs.ReadDir` differs from the
            // original call shape; in-workspace self-bindings (Rust
            // `use foo::{self}`) also try the rewrite because the
            // workspace decl might be qualified differently.
            if let Some(target) = alias_target {
                let rewritten = format!("{target}.{alias_tail}");
                candidates = lookup(&rewritten);
            }
        }
        if !candidates.is_empty() {
            let (kind, precision) = if candidates.len() == 1 {
                (EdgeKind::Direct, Precision::Narrowed)
            } else {
                (EdgeKind::Virtual, Precision::OverApproximate)
            };
            return candidates
                .into_iter()
                .map(|func| ResolvedCallee {
                    func,
                    kind,
                    precision,
                })
                .collect();
        }
    }
    if module_alias_call {
        return Vec::new();
    }
    let tail = short_tail(lookup_name);
    let resolved_name = aliases.get(tail).map(String::as_str).unwrap_or(tail);
    let used_tail_fallback = resolved_name != lookup_name;
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
    let (kind, precision) = if candidates.len() == 1 && !used_tail_fallback {
        (EdgeKind::Direct, Precision::Narrowed)
    } else {
        (EdgeKind::Virtual, Precision::OverApproximate)
    };
    candidates
        .into_iter()
        .map(|func| ResolvedCallee {
            func,
            kind,
            precision,
        })
        .collect()
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

fn qualified_module_alias_call(name: &str, aliases: &AHashMap<String, String>) -> bool {
    let Some((head, _)) = split_qualified_head_tail(name) else {
        return false;
    };
    aliases.contains_key(head)
}

fn qualified_alias_tail<'a>(name: &'a str, aliases: &AHashMap<String, String>) -> Option<&'a str> {
    let (head, tail) = split_qualified_head_tail(name)?;
    aliases.contains_key(head).then_some(tail)
}

fn alias_head_target<'a>(name: &'a str, aliases: &'a AHashMap<String, String>) -> Option<&'a str> {
    let (head, _) = split_qualified_head_tail(name)?;
    aliases.get(head).map(String::as_str)
}

fn namespace_alias_target_tail<'a>(
    name: &'a str,
    alias_targets: &'a AHashMap<String, AliasTarget>,
) -> Option<(&'a str, &'a str)> {
    let (head, tail) = split_qualified_head_tail(name)?;
    match alias_targets.get(head)? {
        AliasTarget::Namespace { module } if !module.is_empty() && !tail.is_empty() => {
            Some((module.as_str(), tail))
        }
        _ => None,
    }
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
    let resolve = |name: &str| -> Vec<FuncId> {
        let Some((caller_file, caller_module)) = caller_ctx else {
            return Vec::new();
        };
        let ctx = ResolveContext::new(*caller_file, caller_module).with_alias_map(alias_targets);
        resolve_callable_with_context(&global, name, &ctx)
    };
    let caller_export_aliases = caller_ctx
        .and_then(|(file, _)| db.adapter_for(*file))
        .map(|adapter| adapter.capabilities().module_export_aliases)
        .unwrap_or(&[]);
    for func in export_name_variants(alias_tail, caller_export_aliases)
        .into_iter()
        .flat_map(|name| resolve(&name))
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

// `module_target_matches_decl_module_path` lives in
// `bonsai_resolve` so the callgraph, taint, and resolve passes
// share one canonical alias-target match.
use bonsai_resolve::module_target_matches_decl_module_path;

/// Expand a bare alias-tail into every fully-qualified shape that
/// resolves to the same callee. Each language declares its own
/// export-receiver aliases via `LanguageCapabilities::module_export_aliases`
/// (JS/TS: `["exports", "module.exports"]`; languages without this
/// convention pass `&[]`). Mirrors callgraph's `export_name_variants`
/// so both passes use one source of truth.
fn export_name_variants(alias_tail: &str, caller_export_aliases: &[&'static str]) -> Vec<String> {
    let mut variants = vec![alias_tail.to_string()];
    for receiver in caller_export_aliases {
        variants.push(format!("{receiver}.{alias_tail}"));
    }
    variants
}

fn module_target_matches_path(alias_target: &str, file_path: &str) -> bool {
    let target = alias_target.replace('\\', "/");
    let path = file_path.replace('\\', "/");
    let target_parts = module_import_parts(&target);
    let path_parts = module_path_parts(&path);
    let Some(target_leaf) = target_parts.last() else {
        return false;
    };
    if path_parts
        .last()
        .is_some_and(|file| strip_extension(file) == target_leaf.as_str())
    {
        return true;
    }
    if path_parts
        .iter()
        .rev()
        .nth(1)
        .is_some_and(|parent| parent == target_leaf)
    {
        return true;
    }
    if target_parts.len() > path_parts.len() {
        return false;
    }
    path_parts
        .windows(target_parts.len())
        .any(|window| window == target_parts)
}

fn module_import_parts(text: &str) -> Vec<String> {
    let parts: Vec<&str> = if text.contains('/') {
        text.split('/').collect()
    } else {
        text.split('.').collect()
    };
    parts
        .into_iter()
        .filter_map(|part| {
            let part = part.trim();
            (!part.is_empty() && part != "." && part != "..").then(|| strip_extension(part).to_string())
        })
        .collect()
}

fn module_path_parts(text: &str) -> Vec<String> {
    text.split('/')
        .filter_map(|part| {
            let part = part.trim();
            (!part.is_empty() && part != "." && part != "..").then(|| strip_extension(part).to_string())
        })
        .collect()
}

fn strip_extension(part: &str) -> &str {
    part.rsplit_once('.').map_or(part, |(stem, _)| stem)
}

fn split_qualified_head_tail(name: &str) -> Option<(&str, &str)> {
    if let Some((head, tail)) = name.split_once("::") {
        return Some((head, tail));
    }
    if let Some((head, tail)) = name.split_once('.') {
        return Some((head, tail));
    }
    if let Some((head, tail)) = name.split_once(':') {
        return Some((head, tail));
    }
    None
}

/// Apply one event's taint transfer to `state`. Mirror of the
/// per-event transfer function inside [`crate::intra`] — duplicated
/// here because the inter layer walks events with a custom mid-
/// block step-through cursor that the intra layer doesn't expose.
#[allow(clippy::single_match)] // preserved as `match` for parity with sibling event-walks
pub(super) fn apply_event_transfer(
    event: &FlowEvent,
    state: &mut TokenSet,
    _config: &InterTaintConfig,
    db: Option<&AnalyzerDb>,
    caller: Option<FuncId>,
) {
    match event {
        FlowEvent::Assign {
            target,
            source_name,
            source_call,
            source_call_args,
            source_names,
            span,
        } => {
            if target.is_empty() {
                return;
            }
            let non_call_rhs_tainted = source_call.is_none()
                && assignment_rhs_text(db, *span)
                    .as_deref()
                    .is_some_and(|rhs| arg_text_is_tainted(rhs, state));
            if let Some(rhs) = assignment_rhs_text(db, *span) {
                if assignment_span_lhs_matches_target(db, *span, target)
                    && !named_field_initializers(&rhs).is_empty()
                {
                    let field_updates = named_field_initializers(&rhs);
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
            match source_name.as_deref() {
                Some(src) if arg_text_is_tainted(src, state) => {
                    insert_value_target_taint(state, target);
                }
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
        _ => {}
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
    if !(lowered.starts_with("for ")
        || lowered.starts_with("for(")
        || lowered.starts_with("async for ")
        || lowered.starts_with("foreach ")
        || lowered.starts_with("foreach("))
    {
        return false;
    }
    let Some((binding, _iterable)) = lowered.split_once(" in ").or_else(|| lowered.split_once(" of ")) else {
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
    if direct_value || actual.is_empty() || text_looks_qualified(&actual) {
        insert_value_target_taint(state, param_name);
    }
    let mut mapped_descendant = false;
    if !actual.is_empty() && !text_looks_qualified(&actual) {
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
    if actual.is_empty() || text_looks_qualified(&actual) || !is_bare_identifier_text(&actual) {
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

fn is_bare_identifier_text(text: &str) -> bool {
    let text = text.trim();
    !text.is_empty() && text.chars().all(is_identifier_byteish)
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
        }
    }
    bases
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
// The caller pipeline:
//   1. Walk the callee's events with an assign-chain seed of { param_i }.
//   2. Collect every name that gets assigned to any candidate "return
//      token": `source_name` on Returns is not carried by FlowEvent::Return
//      directly, so we approximate by treating all of the function's
//      tainted identifiers at the exit point as "may be the return value".
//      Conservative: over-approximate if in doubt (security semantics).
//   3. If param_i contributes to the tainted set at function exit, record
//      `i` in the summary.
//
// Summary-cache keyed on `FuncId`. Computed lazily, once per function,
// regardless of how many callers ask. Recursion terminates via a
// visited set.
// ---------------------------------------------------------------------------

// Public summary types live in `inter/summary.rs`; re-exported below.

// `function_summary` (the public accessor) lives in `inter/summary.rs`
// alongside its return type definitions.

#[cfg(test)]
mod tests;
