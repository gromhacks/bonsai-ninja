//! Workspace-wide per-function flow-id cache.
//!
//! For each function, hashes its backward call chains into stable
//! content-addressed `F:` ids. Browse rows look up labels here
//! instead of re-enumerating chains per command. Lives in
//! `bonsai_workspace` (not `bonsai_browse`) so prewarm + invalidation
//! sit on the same lifecycle as [`crate::dataflow::DataFlowCache`].
//!
//! The DFS / FNV-1a hash logic is duplicated from
//! `bonsai_inspect::{chains, flow_id}` (forward dep would cycle).
//! Drift is contained by public-contract tests in `bonsai_inspect`.
//! Per-function DFS is capped at `MAX_CHAINS` / `MAX_PROBES`;
//! truncated functions render with a `…` suffix.

use ahash::{AHashMap, AHashSet};
use bonsai_callgraph::ResolvedCallGraph;
use bonsai_common::{FuncId, Precision, SymbolId};
use bonsai_db::AnalyzerDb;
use bonsai_lang_api::{DeclKind, FlowEvent};
use parking_lot::RwLock;
use rayon::prelude::*;
use std::sync::Arc;

/// Per-function chain cap. Matches `bonsai_inspect`'s `--max-flows`
/// default so the prewarmed id set is a subset of what inspect
/// would render for the same target.
const MAX_CHAINS: usize = 256;
/// Per-function probe budget. Bounds the DFS edges visited at
/// `MAX_PROBES * 16` inside [`enumerate_chains`].
const MAX_PROBES: usize = 1024;
/// Forward-closure depth for the downstream extension appended to
/// each backward chain. Matches `inspect`'s `downstream_resolved`
/// default so the hashed chain matches what inspect would render.
const DOWNSTREAM_DEPTH: usize = 6;
/// Forward-closure breadth. Matches `inspect`'s default.
const DOWNSTREAM_BREADTH: usize = 12;
/// Maximum IDs surfaced in one browse `flows` cell. Large hub
/// functions in real-world repos can have hundreds of valid upstream
/// chains; browse tables are an index, not the full trace view, so
/// keep the cell bounded and let `inspect --query` expand the rest.
const MAX_LABELS_PER_FUNC: usize = 32;

#[derive(Default, Debug)]
pub struct FlowIdCache {
    inner: RwLock<Inner>,
}

#[derive(Default, Debug)]
struct Inner {
    /// Shared resolved call graph. Built once on first use and
    /// reused across every `labels_for_func` call — the build
    /// dominates the per-workspace cost on large repos (~1s on
    /// Redis), so amortising it is the big win even for a single
    /// CLI invocation.
    cg: Option<Arc<ResolvedCallGraph>>,
    labels: AHashMap<FuncId, Arc<[String]>>,
    truncated: AHashSet<FuncId>,
    prewarmed: bool,
}

impl FlowIdCache {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Flow-id labels for `func`. O(1) on cache hit; on miss runs a
    /// bounded backward DFS through the shared resolved call graph
    /// (built lazily on first query and cached for every
    /// subsequent call), hashes the chain names, memoises the
    /// result, and returns it.
    ///
    /// The `db` / `vfs` arguments are only used when the resolved
    /// call graph hasn't been built yet or the cache line for
    /// `func` is missing; warm-path calls never touch them.
    pub fn labels_for_func(&self, func: FuncId, db: &AnalyzerDb, vfs: &bonsai_vfs::Vfs) -> Arc<[String]> {
        if let Some(hit) = self.inner.read().labels.get(&func).cloned() {
            return hit;
        }
        let cg = self.call_graph(db, vfs);
        let (chains, trunc) = enumerate_chains(&cg, func, MAX_CHAINS, MAX_PROBES);
        // Mirror `inspect`'s chain extension: each backward chain
        // (root → … → target) gets every resolvable downstream call
        // path DFS-enumerated from its tail. The hashed name sequence
        // — and therefore the flow id — matches what
        // `inspect --query <enclosing_fn>` would emit, so ids from
        // browse paste directly into `inspect --flow F:...`.
        let (ids, label_trunc) = collect_flow_ids_for_chains(&cg, db, chains);
        let arc: Arc<[String]> = Arc::from(ids.into_boxed_slice());
        let mut inner = self.inner.write();
        inner.labels.insert(func, arc.clone());
        if trunc || label_trunc {
            inner.truncated.insert(func);
        }
        arc
    }

    /// Build (or return) the shared resolved call graph. Single
    /// builder lock keeps two concurrent queries from both paying
    /// the build cost.
    fn call_graph(&self, db: &AnalyzerDb, _vfs: &bonsai_vfs::Vfs) -> Arc<ResolvedCallGraph> {
        if let Some(cg) = self.inner.read().cg.clone() {
            return cg;
        }
        let global = db.global_index();
        let built = ResolvedCallGraph::build_with_file_info(
            global.as_ref(),
            |file| bonsai_resolve::alias_map_for_file(&db.imports_for(file)),
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
        );
        let arc = Arc::new(built);
        let mut inner = self.inner.write();
        // Another thread may have raced us — keep whichever landed
        // first so every caller sees the same graph instance.
        if inner.cg.is_none() {
            inner.cg = Some(arc.clone());
        }
        inner.cg.clone().unwrap_or(arc)
    }

    /// `true` when chain enumeration hit its cap for `func` — the
    /// label set is a prefix of reality. Callers surface this as a
    /// trailing `…` in the rendered cell.
    #[must_use]
    pub fn was_truncated(&self, func: FuncId) -> bool {
        self.inner.read().truncated.contains(&func)
    }

    /// How many function entries the next `prewarm_all` call would
    /// compute — used to size the CLI progress bar before any work
    /// happens.
    pub fn pending_count(&self, db: &AnalyzerDb) -> usize {
        let global = db.global_index();
        let already: AHashSet<FuncId> = self.inner.read().labels.keys().copied().collect();
        let mut count = 0usize;
        for file in global.all_files() {
            for d in global.decls_in(file) {
                if matches!(
                    d.kind,
                    DeclKind::Function | DeclKind::Method | DeclKind::Constructor
                ) && !already.contains(&FuncId::new(d.symbol.raw()))
                {
                    count += 1;
                }
            }
        }
        count
    }

    /// Eagerly populate every function's label set in parallel.
    /// `on_each_done` fires once per newly-populated entry (from a
    /// rayon worker, so it must be `Sync`); [`Self::pending_count`]
    /// returns the total up front.
    ///
    /// Skipped by the default CLI path in favour of the lazy
    /// on-demand populate inside [`Self::labels_for_func`] — a
    /// single `browse` invocation typically only needs a handful
    /// of enclosing functions, so paying the build for *every*
    /// function in the workspace would be wasted work. Call this
    /// directly from daemon / LSP startup where the upfront
    /// investment amortises across many queries.
    pub fn prewarm_all_with_progress<F>(&self, db: &AnalyzerDb, vfs: &bonsai_vfs::Vfs, on_each_done: F)
    where
        F: Fn(FuncId) + Sync + Send,
    {
        let cg = self.call_graph(db, vfs);
        let global = db.global_index();
        let already: AHashSet<FuncId> = self.inner.read().labels.keys().copied().collect();
        let mut todo: Vec<FuncId> = Vec::new();
        for file in global.all_files() {
            for decl in global.decls_in(file) {
                if matches!(
                    decl.kind,
                    DeclKind::Function | DeclKind::Method | DeclKind::Constructor
                ) {
                    let func_id = FuncId::new(decl.symbol.raw());
                    if !already.contains(&func_id) {
                        todo.push(func_id);
                    }
                }
            }
        }
        if todo.is_empty() {
            self.inner.write().prewarmed = true;
            return;
        }
        let results: Vec<(FuncId, Arc<[String]>, bool)> = todo
            .par_iter()
            .map(|&f| {
                let (chains, trunc) = enumerate_chains(&cg, f, MAX_CHAINS, MAX_PROBES);
                let (ids, label_trunc) = collect_flow_ids_for_chains(&cg, db, chains);
                on_each_done(f);
                (f, Arc::from(ids.into_boxed_slice()), trunc || label_trunc)
            })
            .collect();
        let mut inner = self.inner.write();
        for (f, ids, trunc) in results {
            inner.labels.insert(f, ids);
            if trunc {
                inner.truncated.insert(f);
            }
        }
        inner.prewarmed = true;
    }

    /// No-progress shortcut for tests and callers that don't need
    /// a bar.
    pub fn prewarm_all(&self, db: &AnalyzerDb, vfs: &bonsai_vfs::Vfs) {
        self.prewarm_all_with_progress(db, vfs, |_| {});
    }

    /// Drop every entry. Called by the workspace-wide
    /// invalidation path when a file changes — coarse but correct.
    pub fn invalidate_all(&self) {
        let mut inner = self.inner.write();
        inner.cg = None;
        inner.labels.clear();
        inner.truncated.clear();
        inner.prewarmed = false;
    }
}

fn collect_flow_ids_for_chains(
    cg: &ResolvedCallGraph,
    db: &AnalyzerDb,
    chains: Vec<Vec<FuncId>>,
) -> (Vec<String>, bool) {
    let mut seen: AHashSet<String> = AHashSet::new();
    let mut truncated = false;
    'chains: for chain in chains {
        for extended in enumerate_call_paths_from(cg, db, &chain, DOWNSTREAM_DEPTH, DOWNSTREAM_BREADTH) {
            let names: Vec<String> = extended
                .iter()
                .map(|&fi| func_display_name(db, fi))
                .filter(|n| !n.is_empty())
                .collect();
            if names.is_empty() {
                continue;
            }
            seen.insert(compute_flow_id(&names));
            if seen.len() >= MAX_LABELS_PER_FUNC {
                truncated = true;
                break 'chains;
            }
        }
    }
    let mut ids: Vec<String> = seen.into_iter().collect();
    ids.sort();
    (ids, truncated)
}

/// Look up a function's display name via the analyzer DB's global
/// index. Returns empty when the function id isn't known (e.g.
/// external / unresolved).
fn func_display_name(db: &AnalyzerDb, func: FuncId) -> String {
    let sym = bonsai_common::SymbolId::new(func.raw());
    db.global_index()
        .decl_of(sym)
        .map(|d| d.name.clone())
        .unwrap_or_default()
}

/// Stable content-hash of a chain's display names. Frozen format:
/// `F:` + 16 lowercase hex of a null-separated FNV-1a digest.
///
/// Same digest body as `bonsai_inspect::compute_flow_id`. Both call
/// into `bonsai_hash` so the digest is RFC-fixed in one place rather
/// than re-derived to break a previous workspace → inspect cycle.
#[must_use]
pub fn compute_flow_id(chain_names: &[String]) -> String {
    format!("F:{:016x}", bonsai_hash::fnv1a_names64(chain_names))
}

/// DFS-enumerate every syntactic call path starting from the tail of
/// `base`. Mirrors `bonsai_cli::commands::inspect::enumerate_call_paths_from`;
/// kept here rather than delegating because this crate is a dep of
/// `bonsai_inspect`. An edge `caller → callee` is included only when
/// the caller's flow events contain a real call to `callee.name` —
/// the same syntactic-pin check that drops `(over-approx)` edges
/// from inspect's render.
fn enumerate_call_paths_from(
    cg: &ResolvedCallGraph,
    db: &AnalyzerDb,
    base: &[FuncId],
    max_extra: usize,
    max_paths: usize,
) -> Vec<Vec<FuncId>> {
    if base.is_empty() {
        return Vec::new();
    }
    let global = db.global_index();
    let mut out: Vec<Vec<FuncId>> = Vec::new();
    let mut stack: Vec<(Vec<FuncId>, usize)> = vec![(base.to_vec(), 0)];
    while let Some((path, extra)) = stack.pop() {
        if out.len() >= max_paths {
            break;
        }
        let Some(&tail) = path.last() else {
            continue;
        };
        let Some(tail_decl) = global.decl_of(SymbolId::new(tail.raw())) else {
            out.push(path);
            continue;
        };
        if extra >= max_extra {
            out.push(path);
            continue;
        }
        let mut resolvable: Vec<FuncId> = cg
            .callees_of(tail)
            .map(|e| e.to)
            .filter(|c| {
                if path.contains(c) {
                    return false;
                }
                let Some(callee_decl) = global.decl_of(SymbolId::new(c.raw())) else {
                    return false;
                };
                find_call_span(&tail_decl.flow_events, &callee_decl.name)
            })
            .collect();
        if resolvable.is_empty() {
            out.push(path);
            continue;
        }
        resolvable.sort_by_key(|f| f.raw());
        for c in resolvable.into_iter().rev() {
            let mut next = path.clone();
            next.push(c);
            stack.push((next, extra + 1));
        }
    }
    if out.is_empty() {
        out.push(base.to_vec());
    }
    out
}

/// True when `events` contains a call to `target` (or `*.target`).
/// Mirrors the helper of the same name in `bonsai_cli` — kept here
/// to avoid a workspace → cli reverse dep.
fn find_call_span(events: &[FlowEvent], target: &str) -> bool {
    for e in events {
        match e {
            FlowEvent::Call {
                name, receiver, args, ..
            } => {
                if name == target || name.ends_with(&format!(".{target}")) {
                    return true;
                }
                if receiver.is_some()
                    && args
                        .iter()
                        .any(|arg| bonsai_lang_api::kit::short_name_of(arg.value_text.trim()) == target)
                {
                    return true;
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } if find_call_span(then_events, target) || find_call_span(else_events, target) => {
                return true;
            }
            FlowEvent::Loop { body, .. } if find_call_span(body, target) => return true,
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } if find_call_span(body, target)
                || find_call_span(catch_events, target)
                || find_call_span(finally_events, target) =>
            {
                return true;
            }
            _ => {}
        }
    }
    false
}

/// Backward DFS over `cg` from `target` to its roots. Returns the
/// chain paths (entry → target) as slices of [`FuncId`]; a
/// `truncated` flag is set when either the chain cap or the probe
/// budget was hit. Precision is not returned here because the
/// flow-id cache doesn't surface it — the separate [`FlowIdCache`]
/// only stores the hashed names.
///
/// Duplicated from `bonsai_inspect::chains::enumerate_chains_resolved`
/// for the same cycle-avoidance reason as [`compute_flow_id`].
fn enumerate_chains(
    cg: &ResolvedCallGraph,
    target: FuncId,
    max_chains: usize,
    max_probes: usize,
) -> (Vec<Vec<FuncId>>, bool) {
    let mut results: Vec<Vec<FuncId>> = Vec::new();
    // DFS uses a (path-reversed, path-set, precision) stack so cycle
    // detection is O(1) per edge instead of O(N) `path_rev.contains`.
    // Mirrors the shape used by
    // `bonsai_inspect::chains::enumerate_chains_resolved`; the two
    // are duplicated for the cycle-avoidance reason in
    // [`compute_flow_id`].
    let mut initial_set = ahash::AHashSet::new();
    initial_set.insert(target);
    let mut stack: Vec<(Vec<FuncId>, ahash::AHashSet<FuncId>, Precision)> =
        vec![(vec![target], initial_set, Precision::Exact)];
    let mut visited_budget: usize = 0;
    let mut truncated = false;
    // Mirror inspect's `pushed_any_parent` shape so cycle handling
    // doesn't over-emit. inspect only emits when ALL parents are
    // cyclic (no extension was pushed); a cycle edge alongside
    // valid parents must NOT push a partial chain — that would
    // make browse F: IDs over-count vs `inspect --flow F:…`,
    // breaking the documented "paste from browse into inspect"
    // contract.
    let mut emitted_chains: ahash::AHashSet<Vec<FuncId>> = ahash::AHashSet::new();
    while let Some((path_rev, path_set, _prec)) = stack.pop() {
        if results.len() >= max_chains {
            truncated = true;
            break;
        }
        visited_budget += 1;
        if visited_budget > max_probes.saturating_mul(16) {
            truncated = true;
            break;
        }
        let Some(&tip) = path_rev.last() else {
            continue;
        };
        let callers: Vec<_> = cg.callers_of(tip).collect();
        let mut pushed_any_parent = false;
        for edge in callers {
            if path_set.contains(&edge.from) {
                continue; // skip cycle edge; emit only if ALL parents cycle
            }
            let mut extended = path_rev.clone();
            extended.push(edge.from);
            let mut next_set = path_set.clone();
            next_set.insert(edge.from);
            stack.push((extended, next_set, Precision::Exact));
            pushed_any_parent = true;
        }
        if !pushed_any_parent {
            // Either an entry point (no callers) or every caller
            // was cyclic. Emit the path-so-far once.
            let mut chain = path_rev;
            chain.reverse();
            if emitted_chains.insert(chain.clone()) {
                results.push(chain);
            }
        }
    }
    (results, truncated)
}
