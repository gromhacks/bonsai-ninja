//! Workspace-level cache of per-entry seed-free value-flow graphs.
//!
//! Wraps `bonsai_taint::value_flow_for_function` in a per-FuncId
//! cache, mirroring the persistence + invalidation shape of
//! [`super::dataflow::DataFlowCache`] but with one canonical seed
//! strategy (self-provenance). Security uses these graphs for
//! source-node selection before it runs exact source-seeded taint
//! paths.

use ahash::{AHashMap, AHashSet};
use bonsai_common::{workspace_bonsai_dir, FuncId, MATCHER_POLICY_FINGERPRINT};
use bonsai_db::AnalyzerDb;
use bonsai_lang_api::DeclKind;
use bonsai_taint::{value_flow_for_function_with_caches, InterTaintCaches, InterTaintConfig};
pub use bonsai_taint::{ValueFlowEdge, ValueFlowGraph, ValueFlowNode, ValueFlowNodeKind};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::{
    ffi::OsString,
    path::{Path, PathBuf},
    process,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};

/// On-disk format version. Bump when the snapshot shape changes
/// (new node kind, edge field, etc.) so old sidecars are rejected.
pub const VALUE_FLOW_CACHE_VERSION: u32 = 2;
static VALUE_FLOW_TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Cache of `ValueFlowGraph` per entry function.
///
/// Built lazily via `graph_for(func, db)` and shared across
/// `inspect`/`trace`/`security` queries within a single CLI process.
/// Optional persistence uses a sidecar beside the existing
/// `DataFlowCache`.
#[derive(Default)]
pub struct ValueFlowCache {
    inner: Arc<RwLock<Inner>>,
}

#[derive(Default)]
struct Inner {
    graphs: AHashMap<FuncId, Arc<ValueFlowGraph>>,
    /// Per-FuncId set of seed names whose forward-closure in the
    /// per-entry value-flow graph reaches a `Return` node in the
    /// same function. Precomputed alongside the graph so
    /// `source_seed_reaches_return` becomes a hash-set lookup
    /// instead of a per-seed forward-closure walk.
    returning_seeds: AHashMap<FuncId, Arc<AHashSet<String>>>,
}

impl ValueFlowCache {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Get the value-flow graph for `func`, computing on-demand if
    /// not cached. Always returns an `Arc` so concurrent readers
    /// share one allocation. Uses an ephemeral `InterTaintCaches`
    /// for one-off callers; workspace consumers should prefer
    /// [`Self::graph_for_with_caches`] so the resolver memo + alias
    /// maps survive across calls.
    pub fn graph_for(&self, func: FuncId, db: &AnalyzerDb) -> Arc<ValueFlowGraph> {
        let caches = InterTaintCaches::default();
        self.graph_for_with_caches(func, db, &caches)
    }

    /// Variant of [`Self::graph_for`] that shares the caller's
    /// `InterTaintCaches` so resolver answers, alias maps, and
    /// function summaries persist across invocations. The workspace
    /// passes its singleton from [`super::Workspace::inter_taint_caches`].
    pub fn graph_for_with_caches(
        &self,
        func: FuncId,
        db: &AnalyzerDb,
        caches: &InterTaintCaches,
    ) -> Arc<ValueFlowGraph> {
        // Bind the read-lock probe to a `let` so the guard's
        // temporary ends at the `;` before we acquire the write
        // lock below. parking_lot::RwLock is non-reentrant; the
        // if-let-scrutinee form would extend the read guard's
        // lifetime through the rest of the function and deadlock
        // on the upgrade. Same hazard B1 hit; documented in
        // design-patterns.mdx §13a.
        let cached = self.inner.read().graphs.get(&func).cloned();
        if let Some(hit) = cached {
            return hit;
        }
        let graph = value_flow_for_function_with_caches(func, db, &InterTaintConfig::default(), caches);
        let arc = Arc::new(graph);
        let returning = Arc::new(compute_returning_seed_names(&arc, func));
        let mut inner = self.inner.write();
        inner.graphs.insert(func, arc.clone());
        inner.returning_seeds.insert(func, returning);
        arc
    }

    /// Set of seed names whose forward closure in `func`'s
    /// value-flow graph reaches a `Return` node in `func`.
    /// Materialised at graph-build time; used by
    /// `source_seed_reaches_return` to answer "does any of these
    /// seeds reach a return?" with a single set intersection
    /// instead of a per-seed forward-closure walk.
    pub fn returning_seed_names(
        &self,
        func: FuncId,
        db: &AnalyzerDb,
        caches: &InterTaintCaches,
    ) -> Arc<AHashSet<String>> {
        let cached = self.inner.read().returning_seeds.get(&func).cloned();
        if let Some(hit) = cached {
            return hit;
        }
        // Force the graph to build, which populates `returning_seeds`
        // as a side effect — simplest way to keep both stores in sync.
        let _ = self.graph_for_with_caches(func, db, caches);
        self.inner
            .read()
            .returning_seeds
            .get(&func)
            .cloned()
            .unwrap_or_else(|| Arc::new(AHashSet::default()))
    }

    /// Eagerly compute graphs for every callable function. Reuses
    /// rayon to parallelise (mirrors `DataFlowCache::prewarm_all`).
    /// Provisions a fresh `InterTaintCaches` per worker — fine for
    /// one-off callers; workspace prewarm uses
    /// [`Self::prewarm_all_with_caches`] so the singleton accumulates.
    pub fn prewarm_all(&self, db: &AnalyzerDb) {
        let caches = InterTaintCaches::default();
        self.prewarm_all_with_caches(db, &caches);
    }

    /// Variant of [`Self::prewarm_all`] that fans out across the
    /// workspace using the caller's shared `InterTaintCaches`.
    /// Accumulating resolver answers across the prewarm fold means
    /// the post-prewarm singleton is already hot for security's
    /// per-source taint runs.
    pub fn prewarm_all_with_caches(&self, db: &AnalyzerDb, caches: &InterTaintCaches) {
        use rayon::prelude::*;
        let global = db.global_index();
        let mut funcs: Vec<FuncId> = Vec::new();
        for file in global.all_files() {
            for d in global.decls_in(file) {
                if matches!(
                    d.kind,
                    DeclKind::Function | DeclKind::Method | DeclKind::Constructor
                ) {
                    funcs.push(FuncId::new(d.symbol.raw()));
                }
            }
        }
        let already: AHashSet<FuncId> = self.inner.read().graphs.keys().copied().collect();
        let todo: Vec<FuncId> = funcs.into_iter().filter(|f| !already.contains(f)).collect();
        if todo.is_empty() {
            return;
        }
        let computed: Vec<(FuncId, Arc<ValueFlowGraph>, Arc<AHashSet<String>>)> = todo
            .par_iter()
            .map(|&f| {
                let graph = Arc::new(value_flow_for_function_with_caches(
                    f,
                    db,
                    &InterTaintConfig::default(),
                    caches,
                ));
                let returning = Arc::new(compute_returning_seed_names(&graph, f));
                (f, graph, returning)
            })
            .collect();
        let mut inner = self.inner.write();
        for (f, graph, returning) in computed {
            inner.graphs.insert(f, graph);
            inner.returning_seeds.insert(f, returning);
        }
    }

    /// Forward transitive closure from `node` across the per-function
    /// graph cache. Crosses function boundaries via call edges that
    /// the per-entry graph already records.
    #[must_use]
    pub fn forward_closure(&self, start: &ValueFlowNode, db: &AnalyzerDb) -> AHashSet<ValueFlowNode> {
        let graph = self.graph_for(start.func, db);
        graph.forward_closure(start)
    }

    /// Backward transitive closure from `node`.
    #[must_use]
    pub fn backward_closure(&self, start: &ValueFlowNode, db: &AnalyzerDb) -> AHashSet<ValueFlowNode> {
        let graph = self.graph_for(start.func, db);
        graph.backward_closure(start)
    }

    /// Select every node in the cached graph for `func` matching
    /// `predicate`. Used by rule-match selectors to find starting
    /// points for a security source rule.
    pub fn nodes_matching<F>(&self, func: FuncId, db: &AnalyzerDb, predicate: F) -> Vec<ValueFlowNode>
    where
        F: Fn(&ValueFlowNode) -> bool,
    {
        let graph = self.graph_for(func, db);
        graph.nodes.iter().filter(|n| predicate(n)).cloned().collect()
    }

    /// Enumerate paths from `src` to `dst` up to `max_paths`. DFS with
    /// a visited set per path; cycles terminate. Returns each path as
    /// a sequence of nodes.
    pub fn paths(
        &self,
        src: &ValueFlowNode,
        dst: &ValueFlowNode,
        db: &AnalyzerDb,
        max_paths: usize,
    ) -> Vec<Vec<ValueFlowNode>> {
        if max_paths == 0 || src == dst {
            return Vec::new();
        }
        let graph = self.graph_for(src.func, db);
        let mut out = Vec::new();
        let mut stack: Vec<(ValueFlowNode, Vec<ValueFlowNode>, AHashSet<ValueFlowNode>)> =
            vec![(src.clone(), vec![src.clone()], {
                let mut seen = AHashSet::default();
                seen.insert(src.clone());
                seen
            })];
        while let Some((cur, path, seen)) = stack.pop() {
            if out.len() >= max_paths {
                break;
            }
            if &cur == dst {
                out.push(path);
                continue;
            }
            if let Some(edges) = graph.forward.get(&cur) {
                for ValueFlowEdge { to, .. } in edges {
                    if seen.contains(to) {
                        continue;
                    }
                    let mut next_path = path.clone();
                    next_path.push(to.clone());
                    let mut next_seen = seen.clone();
                    next_seen.insert(to.clone());
                    stack.push((to.clone(), next_path, next_seen));
                }
            }
        }
        out
    }

    /// Number of cached graphs.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.read().graphs.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn clear(&self) {
        let mut inner = self.inner.write();
        inner.graphs.clear();
        inner.returning_seeds.clear();
    }

    /// Conventional sidecar path under `workspace_root/.bonsai/`.
    #[must_use]
    pub fn sidecar_path(workspace_root: &Path) -> PathBuf {
        workspace_bonsai_dir(workspace_root).join(format!("value_flow.v{VALUE_FLOW_CACHE_VERSION}.bin"))
    }

    /// Serialize all cached graphs to disk as a versioned bincode
    /// blob. Mirrors `DataFlowCache::save_to_disk`'s atomic-rename
    /// shape so partial writes can't survive a crash.
    pub fn save_to_disk(&self, path: &Path) -> std::io::Result<()> {
        let snap = self.snapshot();
        let bytes =
            bincode::serialize(&snap).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        // Write to a temp file first, then atomic-rename — avoids leaving a
        // half-written sidecar on the path if the process is killed mid-write.
        let tmp_path = unique_value_flow_tmp_path(path);
        {
            use std::io::Write;
            let mut tmp_file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&tmp_path)?;
            tmp_file.write_all(&bytes)?;
            tmp_file.sync_all()?;
        }
        if let Err(err) = std::fs::rename(&tmp_path, path) {
            // Best-effort cleanup of the orphan temp file.
            let _ = std::fs::remove_file(&tmp_path);
            return Err(err);
        }
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                if let Ok(dir) = std::fs::File::open(parent) {
                    let _ = dir.sync_all();
                }
            }
        }
        Ok(())
    }

    /// Load from a sidecar written by `save_to_disk`. Returns the
    /// number of entries that survived version validation. Non-
    /// existent sidecar returns `Ok(0)` (nothing to load, not an
    /// error). Version-mismatch / corrupt blob returns `Ok(0)` after
    /// logging.
    pub fn load_from_disk(&self, path: &Path) -> std::io::Result<usize> {
        if !path.exists() {
            return Ok(0);
        }
        let bytes = std::fs::read(path)?;
        let snap: SerializableValueFlowSnapshot = match bincode::deserialize(&bytes) {
            Ok(s) => s,
            Err(error) => {
                tracing::warn!(
                    path = %path.display(),
                    error = %error,
                    "ignoring corrupt value-flow sidecar"
                );
                return Ok(0);
            }
        };
        if snap.version != VALUE_FLOW_CACHE_VERSION {
            tracing::warn!(
                path = %path.display(),
                version = snap.version,
                expected = VALUE_FLOW_CACHE_VERSION,
                "ignoring value-flow sidecar with version mismatch"
            );
            return Ok(0);
        }
        if snap.matcher_policy_fingerprint != MATCHER_POLICY_FINGERPRINT {
            // Matcher policy changed — graphs may not reflect
            // current rule semantics. Drop.
            return Ok(0);
        }
        let mut inner = self.inner.write();
        let mut loaded = 0;
        for entry in snap.entries {
            let func = FuncId::new(entry.func_raw);
            inner.graphs.insert(func, Arc::new(entry.graph));
            loaded += 1;
        }
        Ok(loaded)
    }

    /// In-memory snapshot of the cache for tests, daemon checkpoints,
    /// and SDK consumers that want to ship the cache shape across
    /// process boundaries without going through disk. Mirrors
    /// `DataFlowCache::snapshot`.
    #[must_use]
    pub fn snapshot(&self) -> SerializableValueFlowSnapshot {
        let inner = self.inner.read();
        let entries = inner
            .graphs
            .iter()
            .map(|(func, graph)| SerializableValueFlowEntry {
                func_raw: func.raw(),
                graph: (**graph).clone(),
            })
            .collect();
        SerializableValueFlowSnapshot {
            version: VALUE_FLOW_CACHE_VERSION,
            matcher_policy_fingerprint: MATCHER_POLICY_FINGERPRINT,
            entries,
        }
    }

    /// Restore from an in-memory snapshot, applying the same
    /// version + matcher-policy-fingerprint validation as
    /// `load_from_disk`. Returns the number of entries that
    /// survived; mismatched fingerprints invalidate everything.
    pub fn load_snapshot(&self, snap: SerializableValueFlowSnapshot) -> usize {
        if snap.version != VALUE_FLOW_CACHE_VERSION {
            return 0;
        }
        if snap.matcher_policy_fingerprint != MATCHER_POLICY_FINGERPRINT {
            return 0;
        }
        let mut inner = self.inner.write();
        let mut loaded = 0;
        for entry in snap.entries {
            let func = FuncId::new(entry.func_raw);
            inner.graphs.insert(func, Arc::new(entry.graph));
            loaded += 1;
        }
        loaded
    }
}

/// Names of `Param` / `AssignTarget` nodes in `func`'s value-flow
/// graph whose forward closure reaches a `Return` node in `func`.
/// Built once at graph-build time so per-source "does this seed
/// reach a return?" queries collapse to a hash-set membership
/// check.
fn compute_returning_seed_names(graph: &ValueFlowGraph, func: FuncId) -> AHashSet<String> {
    let mut out: AHashSet<String> = AHashSet::default();
    let mut return_nodes: Vec<&ValueFlowNode> = Vec::new();
    let mut origin_nodes: Vec<&ValueFlowNode> = Vec::new();
    for node in &graph.nodes {
        if node.func != func {
            continue;
        }
        match node.kind {
            ValueFlowNodeKind::Return => return_nodes.push(node),
            ValueFlowNodeKind::Param | ValueFlowNodeKind::AssignTarget => {
                origin_nodes.push(node);
            }
            _ => {}
        }
    }
    if return_nodes.is_empty() || origin_nodes.is_empty() {
        return out;
    }
    // Forward-walk every origin once and record which ones reach a
    // Return. This is O(N²) per function but `N` is small (params +
    // local assign-targets); the alternative would be to backward-
    // walk from Returns, but the graph already provides forward
    // edges and we only care about origin names — not the full path.
    for origin in origin_nodes {
        let reach = graph.forward_closure(origin);
        if reach.iter().any(|n| {
            n.func == func && matches!(n.kind, ValueFlowNodeKind::Return)
        }) {
            out.insert(origin.value_text.clone());
        }
    }
    out
}

fn unique_value_flow_tmp_path(path: &Path) -> PathBuf {
    let counter = VALUE_FLOW_TMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut name = path
        .file_name()
        .map(OsString::from)
        .unwrap_or_else(|| OsString::from("value_flow.v1.bin"));
    name.push(format!(".tmp.{}.{}", process::id(), counter));
    path.with_file_name(name)
}

/// On-disk snapshot. Round-trips via bincode.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SerializableValueFlowSnapshot {
    pub version: u32,
    pub matcher_policy_fingerprint: u128,
    pub entries: Vec<SerializableValueFlowEntry>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SerializableValueFlowEntry {
    pub func_raw: u32,
    pub graph: ValueFlowGraph,
}

#[cfg(test)]
mod tests {
    use super::*;
    use bonsai_lang_api::{AdapterArc, LanguageRegistry};
    use bonsai_taint::ValueFlowNodeKind;
    use bonsai_vfs::Vfs;
    use std::sync::Arc;

    fn build_db_with(files: &[(&str, &str)], adapter: AdapterArc) -> AnalyzerDb {
        let vfs = Arc::new(Vfs::new());
        for (path, source) in files {
            vfs.write((*path).to_string(), Arc::<str>::from(*source));
        }
        let registry = Arc::new(LanguageRegistry::new());
        registry.register(adapter);
        let db = AnalyzerDb::new(vfs, registry);
        for file in db.vfs().all_files() {
            let _ = db.decl_index(file);
        }
        db
    }

    #[test]
    fn cache_hits_share_arc() {
        let adapter: AdapterArc = Arc::new(bonsai_lang_python::PythonAdapter::new());
        let db = build_db_with(
            &[(
                "a.py",
                "def entry(args):\n    helper(args)\n\ndef helper(p):\n    sink(p)\n",
            )],
            adapter,
        );
        let entry = bonsai_resolve::resolve_callable(&db.global_index(), "entry")
            .into_iter()
            .next()
            .expect("entry resolves");
        let cache = ValueFlowCache::new();
        let g1 = cache.graph_for(entry, &db);
        let g2 = cache.graph_for(entry, &db);
        assert!(Arc::ptr_eq(&g1, &g2), "second hit must reuse Arc");
    }

    #[test]
    fn nodes_matching_finds_param() {
        let adapter: AdapterArc = Arc::new(bonsai_lang_python::PythonAdapter::new());
        let db = build_db_with(
            &[(
                "a.py",
                "def entry(args):\n    helper(args)\n\ndef helper(p):\n    sink(p)\n",
            )],
            adapter,
        );
        let entry = bonsai_resolve::resolve_callable(&db.global_index(), "entry")
            .into_iter()
            .next()
            .expect("entry resolves");
        let cache = ValueFlowCache::new();
        let nodes = cache.nodes_matching(entry, &db, |n| {
            n.kind == ValueFlowNodeKind::Param && n.value_text == "args"
        });
        assert_eq!(nodes.len(), 1, "should find exactly one args param");
    }

    #[test]
    fn sidecar_roundtrip_preserves_graphs() {
        let adapter: AdapterArc = Arc::new(bonsai_lang_python::PythonAdapter::new());
        let db = build_db_with(
            &[(
                "a.py",
                "def entry(args):\n    helper(args)\n\ndef helper(p):\n    sink(p)\n",
            )],
            adapter,
        );
        let entry = bonsai_resolve::resolve_callable(&db.global_index(), "entry")
            .into_iter()
            .next()
            .expect("entry resolves");
        let cache = ValueFlowCache::new();
        let _ = cache.graph_for(entry, &db);
        let initial_len = cache.len();
        assert!(initial_len >= 1, "should have cached at least one graph");

        let tmp = std::env::temp_dir().join(format!("value_flow_test_{}.bin", std::process::id()));
        cache.save_to_disk(&tmp).expect("save to disk succeeds");

        let restored = ValueFlowCache::new();
        let loaded = restored.load_from_disk(&tmp).expect("load from disk succeeds");
        assert_eq!(loaded, initial_len, "loaded count must match saved count");

        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn sidecar_tmp_paths_are_unique_per_write() {
        let path = Path::new("/tmp/value_flow.v1.bin");
        let first = unique_value_flow_tmp_path(path);
        let second = unique_value_flow_tmp_path(path);

        assert_ne!(first, second);
        assert_eq!(first.parent(), path.parent());
        assert!(first
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with("value_flow.v1.bin.tmp.")));
    }

    #[test]
    fn load_from_nonexistent_sidecar_returns_zero() {
        let cache = ValueFlowCache::new();
        let n = cache
            .load_from_disk(Path::new("/tmp/value_flow_does_not_exist_xyz.bin"))
            .expect("nonexistent path is not an error");
        assert_eq!(n, 0);
    }

    #[test]
    fn forward_closure_via_cache_reaches_callee_param() {
        let adapter: AdapterArc = Arc::new(bonsai_lang_python::PythonAdapter::new());
        let db = build_db_with(
            &[(
                "a.py",
                "def entry(args):\n    helper(args)\n\ndef helper(p):\n    sink(p)\n",
            )],
            adapter,
        );
        let entry = bonsai_resolve::resolve_callable(&db.global_index(), "entry")
            .into_iter()
            .next()
            .expect("entry resolves");
        let cache = ValueFlowCache::new();
        let nodes = cache.nodes_matching(entry, &db, |n| {
            n.kind == ValueFlowNodeKind::Param && n.value_text == "args"
        });
        let origin = nodes.into_iter().next().expect("origin exists");
        let reach = cache.forward_closure(&origin, &db);
        assert!(
            reach.iter().any(|n| n.value_text == "p"),
            "forward closure must reach `p`; got {reach:?}"
        );
    }
}
