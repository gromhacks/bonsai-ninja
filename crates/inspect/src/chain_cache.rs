//! In-process memo cache for hot per-target lookups in inspect /
//! export. Each field is a [`crate::BoundedCache`] (FIFO eviction);
//! evicted entries recompute identically. Keys include budget
//! parameters so a caller can ask for a wider chain set later in
//! the same run without getting a stale truncated answer.

use crate::cache::{
    BoundedCache, CALLEES_CACHE_CAP, CHAINS_CACHE_CAP, DOWNSTREAM_CACHE_CAP, ENCLOSING_CACHE_CAP,
    REACHABLE_CACHE_CAP,
};
use crate::chains::{downstream_funcs_set, enumerate_chains_resolved, ChainTruncation, ResolvedChain};
use bonsai_callgraph::ResolvedCallGraph;
use bonsai_common::{FileId, FuncId, Span};
use bonsai_workspace::Workspace;
use parking_lot::Mutex;
use std::sync::{Arc, OnceLock};

// Cache primitives are `Mutex` (not `RefCell`) so `ChainCache` is
// `Sync` — which lets rayon workers share a single cache during
// parallel per-hit processing in `cmd_inspect`. `parking_lot::Mutex`
// uncontended ≈ 3-5 ns, which is far below the cost of any cache
// operation, so the swap has no measurable effect on single-threaded
// workloads.
//
// Determinism: `BoundedCache` still has FIFO eviction and stable
// insertion order, so replaying the exact same inputs through the
// cache produces the exact same contents regardless of which thread
// inserted. Chain enumeration and filter output are pure functions
// of the workspace, so shared access can't produce different
// results.
type ChainsCache = Mutex<BoundedCache<(FuncId, usize, usize), (Vec<ResolvedChain>, ChainTruncation)>>;
type DownstreamCache = Mutex<BoundedCache<(FuncId, usize, usize), Vec<FuncId>>>;
type ReachableCache = Mutex<BoundedCache<Vec<FuncId>, Vec<FuncId>>>;
type PerFuncTokensCache = Mutex<BoundedCache<FuncId, Arc<bonsai_taint::KindedTokens>>>;
type TaintFactsCache = Mutex<BoundedCache<FuncId, Arc<bonsai_taint::KindedTokens>>>;
type CalleesCache = Mutex<BoundedCache<FuncId, Vec<FuncId>>>;
type EnclosingCache = Mutex<BoundedCache<(FileId, u64, u64), Option<(FuncId, String)>>>;

/// Per-invocation memo cache for the hot per-target lookups
/// inspect's chain enumeration repeats over and over (one walk
/// per hit on the same enclosing function — Redis's
/// `--query system` resolves 50+ hits to a handful of decls, so
/// memoization is the difference between 30 s and 3 s).
///
/// Borrowed from a `&Workspace`; lifetime `'a` is the workspace's.
/// `Sync` so a single cache can be shared across rayon workers
/// during parallel per-hit processing — every internal field is a
/// `parking_lot::Mutex` (uncontended ≈ 3-5 ns) or `OnceLock`.
///
/// Construct with [`ChainCache::new`] for the normal cached path
/// or [`ChainCache::without_cache`] to bypass memoization (used
/// by `--no-cache` and the cold-path benchmarks).
pub struct ChainCache<'a> {
    ws: &'a Workspace,
    /// Resolved, FuncId-keyed call graph. Built lazily once per
    /// cache lifetime. `OnceLock` (not `OnceCell`) so the cache
    /// can initialise under a shared reference across threads
    /// — the first thread to touch it wins; the rest see the
    /// stored value. Stored as `Arc` so we share the workspace's
    /// canonical singleton instead of deep-cloning a 100k-edge
    /// `CallGraph` per inspect invocation.
    pub(crate) resolved: OnceLock<Arc<ResolvedCallGraph>>,
    pub(crate) chains_r: ChainsCache,
    pub(crate) downstream_r: DownstreamCache,
    pub(crate) reachable_r: ReachableCache,
    /// Per-FuncId reachability hop tokens. Chains share many hops,
    /// so caching at this granularity means each hop's tokens
    /// compute exactly once per invocation instead of once per
    /// chain-that-visits-it.
    pub(crate) per_func_tokens_r: PerFuncTokensCache,
    /// Interprocedural taint augmentation facts per entry function.
    /// One entry typically fans out to many chains; running the
    /// interprocedural pass once per entry and re-using the facts
    /// across chains cuts inspect's `--from` / `--to` wall-time
    /// roughly in half on hub-sink queries.
    pub(crate) taint_facts_r: TaintFactsCache,
    pub(crate) callees_r: CalleesCache,
    pub(crate) enclosing: EnclosingCache,
    /// When `true`, every cache method bypasses the memo and
    /// recomputes. Exposed via the top-level `--no-cache` CLI flag
    /// as an escape hatch for benchmarking the cold path and for
    /// guaranteeing a fresh computation if the caller ever suspects
    /// stale state.
    disabled: bool,
}

impl<'a> ChainCache<'a> {
    /// Construct a normal in-process memo cache. Use this for any
    /// command that performs more than a single chain lookup —
    /// `inspect`, `export`, and the per-hit filter passes all
    /// share one cache per CLI invocation. Cache holds bounded
    /// memos; output is identical to [`Self::without_cache`].
    ///
    /// Sanitizer classification does not alter propagation, so every
    /// cache instance reads the same semantic taint facts.
    #[must_use]
    pub fn new(ws: &'a Workspace) -> Self {
        Self::with_disabled(ws, false)
    }

    /// Construct a cache whose methods always take the cold path.
    /// Wires `--no-cache` and the cold-path benchmarks. Output is
    /// bit-for-bit identical to [`Self::new`]; only wall time
    /// differs (every lookup recomputes from scratch).
    #[must_use]
    pub fn without_cache(ws: &'a Workspace) -> Self {
        Self::with_disabled(ws, true)
    }

    /// Construct a cache around an exact query-scoped resolved graph.
    ///
    /// Large-workspace endpoint queries use this when no reusable
    /// partitioned callgraph exists yet. The compiler worklist still reaches
    /// a fixed point, but only from the requested source; presentation must
    /// not replace that graph with the workspace-wide fallback merely to
    /// enumerate chains.
    #[must_use]
    pub fn with_resolved_graph(ws: &'a Workspace, resolved: Arc<ResolvedCallGraph>) -> Self {
        Self::with_disabled_and_resolved(ws, false, resolved)
    }

    /// Query-scoped counterpart to [`Self::without_cache`].
    #[must_use]
    pub fn without_cache_with_resolved_graph(ws: &'a Workspace, resolved: Arc<ResolvedCallGraph>) -> Self {
        Self::with_disabled_and_resolved(ws, true, resolved)
    }

    fn with_disabled_and_resolved(
        ws: &'a Workspace,
        disabled: bool,
        resolved: Arc<ResolvedCallGraph>,
    ) -> Self {
        let cache = Self::with_disabled(ws, disabled);
        cache
            .resolved
            .set(resolved)
            .expect("new chain cache has no resolved graph");
        cache
    }

    fn with_disabled(ws: &'a Workspace, disabled: bool) -> Self {
        Self {
            ws,
            resolved: OnceLock::new(),
            chains_r: Mutex::new(BoundedCache::with_capacity(CHAINS_CACHE_CAP)),
            downstream_r: Mutex::new(BoundedCache::with_capacity(DOWNSTREAM_CACHE_CAP)),
            reachable_r: Mutex::new(BoundedCache::with_capacity(REACHABLE_CACHE_CAP)),
            per_func_tokens_r: Mutex::new(BoundedCache::with_capacity(REACHABLE_CACHE_CAP)),
            taint_facts_r: Mutex::new(BoundedCache::with_capacity(REACHABLE_CACHE_CAP)),
            callees_r: Mutex::new(BoundedCache::with_capacity(CALLEES_CACHE_CAP)),
            enclosing: Mutex::new(BoundedCache::with_capacity(ENCLOSING_CACHE_CAP)),
            disabled,
        }
    }

    /// Drop every memoized entry. The next call to any method
    /// rebuilds from scratch. Safe to call at any point — entries
    /// returned to the caller are owned `Vec`s, not borrows into
    /// the maps, so no live reference is invalidated.
    pub fn reset(&mut self) {
        self.resolved = OnceLock::new();
        self.chains_r.lock().clear();
        self.downstream_r.lock().clear();
        self.reachable_r.lock().clear();
        self.per_func_tokens_r.lock().clear();
        self.taint_facts_r.lock().clear();
        self.callees_r.lock().clear();
        self.enclosing.lock().clear();
    }

    /// Lazy-built workspace-wide resolved call graph. Walks every
    /// function's flow events once and resolves call names through
    /// the alias map + global decl index. Falls through to the
    /// workspace-cached singleton so `inspect`/`security`/`browse`
    /// all share the same allocation.
    pub fn resolved_graph(&self) -> &ResolvedCallGraph {
        self.resolved
            .get_or_init(|| self.ws.cached_resolved_call_graph())
            .as_ref()
    }

    /// Resolved-graph chain enumeration. Eliminates the
    /// `__construct`-class collision bug structurally — chains are
    /// `Vec<FuncId>`, not `Vec<String>`.
    pub fn chains_resolved(
        &self,
        target: FuncId,
        max_chains: usize,
        max_probes: usize,
    ) -> (Vec<ResolvedChain>, ChainTruncation) {
        if self.disabled {
            return enumerate_chains_resolved(self.resolved_graph(), target, max_chains, max_probes);
        }
        let key = (target, max_chains, max_probes);
        if let Some(hit) = self.chains_r.lock().get(&key) {
            return hit.clone();
        }
        let computed = enumerate_chains_resolved(self.resolved_graph(), target, max_chains, max_probes);
        self.chains_r.lock().insert(key, computed.clone());
        computed
    }

    /// Resolved-graph downstream callee closure.
    pub fn downstream_resolved(&self, target: FuncId, max_depth: usize, max_funcs: usize) -> Vec<FuncId> {
        if self.disabled {
            return downstream_funcs_set(self.resolved_graph(), target, max_depth, max_funcs);
        }
        let key = (target, max_depth, max_funcs);
        if let Some(hit) = self.downstream_r.lock().get(&key) {
            return hit.clone();
        }
        let computed = downstream_funcs_set(self.resolved_graph(), target, max_depth, max_funcs);
        self.downstream_r.lock().insert(key, computed.clone());
        computed
    }

    /// Resolved-graph "names visible in the rendered flow." Each
    /// hop in the extended chain plus that hop's direct callees.
    pub fn reachable_resolved(&self, extended_chain: &[FuncId]) -> Vec<FuncId> {
        if self.disabled {
            return funcs_reachable_in_chain(self, extended_chain);
        }
        if let Some(hit) = self.reachable_r.lock().get(extended_chain) {
            return hit.clone();
        }
        let computed = funcs_reachable_in_chain(self, extended_chain);
        self.reachable_r
            .lock()
            .insert(extended_chain.to_vec(), computed.clone());
        computed
    }

    /// Cached per-FuncId reachability tokens. Each hop computed
    /// exactly once per invocation, regardless of how many chains
    /// visit it.
    pub fn per_func_tokens(&self, func: FuncId) -> Arc<bonsai_taint::KindedTokens> {
        if !self.disabled {
            if let Some(hit) = self.per_func_tokens_r.lock().get(&func) {
                return hit.clone();
            }
        }
        let computed = self.ws.name_reachable_kinded_for(func);
        if !self.disabled {
            self.per_func_tokens_r.lock().insert(func, computed.clone());
        }
        computed
    }

    /// Per-entry interprocedural taint facts. Delegates to the
    /// workspace-level [`bonsai_workspace::dataflow::DataFlowCache`]
    /// (pre-warmed at `Workspace::open` time + persisted to
    /// `.bonsai/dataflow.v2.bin`) so repeat queries — across
    /// processes, even — pay the analysis cost once.
    ///
    /// The in-process `taint_facts_r` mirror is kept as a second-
    /// level memo for the hottest path (same entry, many hits per
    /// inspect invocation): reading the `RwLock`-backed workspace
    /// cache is cheap but this extra layer is cheaper still.
    ///
    /// `--no-cache` (`self.disabled`) bypasses both layers and
    /// runs the interprocedural pass cold every call.
    pub fn taint_facts_for_entry(&self, entry: FuncId) -> Arc<bonsai_taint::KindedTokens> {
        if self.disabled {
            return Arc::new(bonsai_taint::taint_facts_for_entry(entry, self.ws.db()));
        }
        if let Some(hit) = self.taint_facts_r.lock().get(&entry) {
            return hit.clone();
        }
        let computed = self.ws.dataflow().facts_for(entry, self.ws.db());
        self.taint_facts_r.lock().insert(entry, computed.clone());
        computed
    }

    /// Union of taint facts across every function on the chain. The
    /// entry's facts include inter-procedural propagation; downstream
    /// hops contribute their own structural facts (param names, local
    /// calls, assignment targets) so filters targeting an intermediate
    /// hop's parameter (e.g. `--to cmd` where `cmd` is a param of
    /// `run_admin_command`) still match via taint-anchored signals
    /// without requiring the entry's interprocedural pass to reach
    /// every downstream name.
    pub fn chain_taint_facts(&self, chain: &[FuncId]) -> Arc<bonsai_taint::KindedTokens> {
        if chain.is_empty() {
            return Arc::new(bonsai_taint::KindedTokens::default());
        }
        let mut merged = bonsai_taint::KindedTokens::default();
        for &func in chain {
            // Interprocedural facts capture propagation from the
            // chosen entry; per-function tokens preserve structural
            // browse facts (args, calls, reads, writes) for every hop
            // on this exact rendered path. Kind filters depend on
            // both: `--from-kind arg token` should match a call-site
            // argument in an intermediate function even when the
            // empty-seed taint pass has no reason to seed that local.
            let facts = self.taint_facts_for_entry(func);
            bonsai_taint::merge_into(&mut merged, &facts);
            let tokens = self.per_func_tokens(func);
            bonsai_taint::merge_into(&mut merged, &tokens);
        }
        Arc::new(merged)
    }

    /// Structural browse facts for exactly the functions on `chain`.
    /// Unlike [`Self::chain_taint_facts`], this does not include
    /// interprocedural entry facts, so it cannot pull in sibling
    /// branches outside the rendered call path.
    pub fn chain_structural_tokens(&self, chain: &[FuncId]) -> Arc<bonsai_taint::KindedTokens> {
        if chain.is_empty() {
            return Arc::new(bonsai_taint::KindedTokens::default());
        }
        let mut merged = bonsai_taint::KindedTokens::default();
        for &func in chain {
            let tokens = self.per_func_tokens(func);
            bonsai_taint::merge_into(&mut merged, &tokens);
        }
        Arc::new(merged)
    }

    /// Parallel pre-warm of the per-entry interprocedural cache.
    /// Takes an iterator of candidate entry FuncIds, de-dupes, skips
    /// anything already cached, and runs the remaining
    /// interprocedural computations on the rayon pool. Results are
    /// bulk-inserted after the parallel computation so worker
    /// threads never contend on per-entry inserts.
    ///
    /// The serial filter loop that runs next hits a hot cache for
    /// every reachability miss instead of running the
    /// interprocedural pass one entry at a time.
    pub fn prewarm_taint_facts<I>(&self, entries: I)
    where
        I: IntoIterator<Item = FuncId>,
    {
        if self.disabled {
            return;
        }
        use rayon::prelude::*;
        let missing: Vec<FuncId> = {
            let cache = self.taint_facts_r.lock();
            let mut seen: ahash::AHashSet<FuncId> = ahash::AHashSet::default();
            entries
                .into_iter()
                .filter(|e| seen.insert(*e) && cache.get(e).is_none())
                .collect()
        };
        if missing.is_empty() {
            return;
        }
        let db = self.ws.db();
        // Inspect can open a syntax-only workspace and still batch exact
        // filter evidence. Prepare the non-default compiler service before
        // entering Rayon so its AST lowering stays parallel and per-entry
        // closures only query the established graph.
        let _compiler_idg = bonsai_taint::compiler_idg_service(db);
        let computed: Vec<(FuncId, Arc<bonsai_taint::KindedTokens>)> = missing
            .into_par_iter()
            .map(|entry| (entry, self.ws.dataflow().facts_for(entry, db)))
            .collect();
        let mut cache = self.taint_facts_r.lock();
        for (entry, facts) in computed {
            cache.insert(entry, facts);
        }
    }

    /// Resolved-graph callees of a single function. Cached so a
    /// chain that revisits the same hop pays the lookup once.
    pub fn callees_of_resolved(&self, func: FuncId) -> Vec<FuncId> {
        if !self.disabled {
            if let Some(hit) = self.callees_r.lock().get(&func) {
                return hit.clone();
            }
        }
        let out: Vec<FuncId> = self
            .resolved_graph()
            .callees_of(func)
            .filter(|edge| edge.precision.is_semantic())
            .map(|edge| edge.to)
            .collect();
        if !self.disabled {
            self.callees_r.lock().insert(func, out.clone());
        }
        out
    }

    /// Memoized enclosing-decl lookup. Returns just the display
    /// name; use [`Self::enclosing_func`] when the FuncId is also
    /// needed.
    pub fn enclosing(&self, file: FileId, decls: &[&bonsai_lang_api::Decl], span: Span) -> Option<String> {
        self.enclosing_func(file, decls, span).map(|(_, n)| n)
    }

    /// Variant of [`Self::enclosing`] that also returns the
    /// resolved [`FuncId`].
    pub fn enclosing_func(
        &self,
        file: FileId,
        decls: &[&bonsai_lang_api::Decl],
        span: Span,
    ) -> Option<(FuncId, String)> {
        if self.disabled {
            return find_enclosing_func(decls, span);
        }
        let key = (file, span.start, span.end);
        if let Some(hit) = self.enclosing.lock().get(&key) {
            return hit.clone();
        }
        let computed = find_enclosing_func(decls, span);
        self.enclosing.lock().insert(key, computed.clone());
        computed
    }
}

/// FuncId-keyed analog of `flow_reachable_names_with`. Returns every
/// FuncId visible in the rendered flow: each hop in the extended
/// chain plus that hop's direct callees in the resolved graph.
/// Deduplicates while preserving insertion order so callers that
/// `find` by name don't re-walk the same FuncId.
fn funcs_reachable_in_chain(cache: &ChainCache<'_>, extended_chain: &[FuncId]) -> Vec<FuncId> {
    let mut reachable: Vec<FuncId> = Vec::with_capacity(extended_chain.len() * 4);
    let mut seen: ahash::AHashSet<FuncId> = ahash::AHashSet::default();
    let mut push = |func: FuncId, out: &mut Vec<FuncId>| {
        if seen.insert(func) {
            out.push(func);
        }
    };
    for &hop_func_id in extended_chain {
        push(hop_func_id, &mut reachable);
        for callee in cache.callees_of_resolved(hop_func_id) {
            push(callee, &mut reachable);
        }
    }
    reachable
}

/// Innermost function/method/constructor decl whose span contains
/// `span`. Returns `(FuncId, decl_name)`.
///
/// Public so the CLI's hit-discovery walk and any other consumer
/// reach the same enclosing-function policy.
pub fn find_enclosing_func(decls: &[&bonsai_lang_api::Decl], span: Span) -> Option<(FuncId, String)> {
    let mut best: Option<&bonsai_lang_api::Decl> = None;
    for decl in decls {
        if !matches!(
            decl.kind,
            bonsai_lang_api::DeclKind::Function
                | bonsai_lang_api::DeclKind::Method
                | bonsai_lang_api::DeclKind::Constructor
        ) {
            continue;
        }
        if decl.span.file != span.file {
            continue;
        }
        if decl.span.start <= span.start && span.end <= decl.span.end {
            // Keep the smallest containing decl so nested functions
            // pick the inner span instead of the outer.
            best = match best {
                None => Some(decl),
                Some(prev) => {
                    if (decl.span.end - decl.span.start) < (prev.span.end - prev.span.start) {
                        Some(decl)
                    } else {
                        Some(prev)
                    }
                }
            };
        }
    }
    best.map(|decl| (FuncId::new(decl.symbol.raw()), decl.name.clone()))
}
