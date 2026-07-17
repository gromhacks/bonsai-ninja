//! Workspace-level cache of per-entry seed-free value-flow graphs.
//!
//! Wraps `bonsai_taint::value_flow_for_function` in a per-FuncId
//! cache, mirroring the persistence + invalidation shape of
//! [`super::dataflow::DataFlowCache`] but with one canonical seed
//! strategy (self-provenance). This is a compatibility projection for
//! navigation/SDK clients; security and native export query the canonical
//! IDG directly.

use crate::cache_fingerprint::{
    dependency_metadata_fingerprint_for_sidecar, discard_stale_factstore_sidecar,
    workspace_content_fingerprint, workspace_content_fingerprint_from_paths,
};
use crate::value_flow_disk::{
    decode as decode_value_flow_entry, encode as encode_value_flow_entry, ValueFlowEntry,
};
use ahash::{AHashMap, AHashSet};
use bonsai_common::{workspace_bonsai_dir, FuncId, MATCHER_POLICY_FINGERPRINT};
use bonsai_db::AnalyzerDb;
use bonsai_factstore::{FactStoreReader, FactStoreWriter};
use bonsai_lang_api::DeclKind;
use bonsai_taint::{value_flow_for_function_with_caches, InterTaintCaches, InterTaintConfig};
pub use bonsai_taint::{ValueFlowEdge, ValueFlowGraph, ValueFlowNode, ValueFlowNodeKind};
use parking_lot::RwLock;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// On-disk format version. Bump when the layout changes so old
/// sidecars are rejected. The workspace-interned factstore format is
/// produced by [`bonsai_factstore`], whose header and pipeline hash reject
/// incompatible payloads before decoding.
// v10 (2026-07-16): MessagePack replaces the retired binary codec.
// v9 (2026-07-16): remove the retired saturation field.
// v8 (2026-05-27): the value-flow graph derives from the IDG, whose
// construction and seeding changed enough to reject older sidecars.
pub const VALUE_FLOW_CACHE_VERSION: u32 = 10;

/// Caller-defined table id stamped into the factstore header. Lets
/// the reader detect "this is the value-flow store" vs other
/// per-function stores when several share a directory.
const VALUE_FLOW_TABLE_ID: u32 = 1;

/// Pipeline-hash field in the factstore header. We fold the matcher
/// policy fingerprint into 64 bits and mix in the current workspace
/// content fingerprint so source changes cannot reuse stale FuncId-
/// keyed graphs.
fn value_flow_pipeline_hash(db: &AnalyzerDb, sidecar_path: &Path) -> u64 {
    value_flow_pipeline_hash_for_content(workspace_content_fingerprint(db), sidecar_path)
}

fn value_flow_pipeline_hash_for_content(content_fingerprint: u64, sidecar_path: &Path) -> u64 {
    let raw = MATCHER_POLICY_FINGERPRINT;
    // Fold the 128-bit fingerprint into 64 bits by xor of halves.
    let lo = raw as u64;
    let hi = (raw >> 64) as u64;
    lo ^ hi
        ^ u64::from(VALUE_FLOW_CACHE_VERSION)
        ^ content_fingerprint
        ^ dependency_metadata_fingerprint_for_sidecar(sidecar_path)
        ^ crate::build_fingerprint_hash()
}

/// Per-function content-address hash used for fine-grained
/// invalidation. v3 ties the entire cache to the matcher policy
/// fingerprint via the file-level pipeline hash and clears on file
/// edits via [`crate::Workspace::ingest_dir`], so per-entry hashes
/// are unused. The field is reserved on the wire so a future version
/// can attach per-function content fingerprints without bumping the
/// fact-store layout.
const RESERVED_BODY_HASH: u64 = 0;

type ValueFlowMemoryEntry = (FuncId, Arc<ValueFlowGraph>, Arc<AHashSet<String>>);

/// Cache of `ValueFlowGraph` per entry function.
///
/// Built lazily via `graph_for(func, db)` and shared across compatibility
/// navigation/SDK queries within a single process. Optional persistence uses
/// a sidecar beside the existing `DataFlowCache`.
#[derive(Default)]
pub struct ValueFlowCache {
    inner: Arc<RwLock<Inner>>,
}

#[derive(Default)]
struct Inner {
    graphs: AHashMap<FuncId, Arc<ValueFlowGraph>>,
    /// Per-FuncId set of seed names whose forward-closure in the
    /// per-entry value-flow graph reaches a `Return` node in the
    /// same function. Precomputed alongside the graph so compatibility
    /// return-summary lookups become a hash-set intersection instead of a
    /// per-seed forward-closure walk.
    returning_seeds: AHashMap<FuncId, Arc<AHashSet<String>>>,
    /// Disk-backed source of truth, populated by either
    /// [`ValueFlowCache::load_from_disk`] or
    /// [`ValueFlowCache::prewarm_to_disk`]. When present, lookups
    /// that miss the in-memory map probe the fact store before
    /// falling through to the engine; the in-memory map then caches
    /// the decoded entry for subsequent hits.
    disk: Option<Arc<FactStoreReader>>,
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
        // Disk probe: when a sidecar / prewarm output is open the
        // entry might already be encoded on disk. Decoding paged
        // bytes is cheaper than re-running the interprocedural pass.
        if let Some(arc) = self.try_hydrate_from_disk(func) {
            return arc;
        }
        let graph = value_flow_for_function_with_caches(func, db, &InterTaintConfig::default(), caches);
        let arc = Arc::new(graph);
        let returning = Arc::new(compute_returning_seed_names(&arc, func));
        let mut inner = self.inner.write();
        inner.graphs.insert(func, arc.clone());
        inner.returning_seeds.insert(func, returning);
        arc
    }

    /// Get the value-flow graph for one immediate consumer without
    /// retaining a freshly-computed graph in the workspace cache.
    ///
    /// This still reuses existing in-memory/disk entries and still
    /// records the compact `returning_seeds` summary. The difference
    /// is the cold-miss behavior: broad compatibility queries may touch
    /// thousands of functions, and retaining every full `ValueFlowGraph` in
    /// RAM defeats the disk-backed cache design.
    /// Callers that need a durable in-process graph cache should use
    /// [`Self::graph_for_with_caches`].
    pub fn graph_for_transient_with_caches(
        &self,
        func: FuncId,
        db: &AnalyzerDb,
        caches: &InterTaintCaches,
    ) -> Arc<ValueFlowGraph> {
        let cached = self.inner.read().graphs.get(&func).cloned();
        if let Some(hit) = cached {
            return hit;
        }
        if let Some(arc) = self.try_hydrate_from_disk(func) {
            return arc;
        }
        let graph = value_flow_for_function_with_caches(func, db, &InterTaintConfig::default(), caches);
        let arc = Arc::new(graph);
        let returning = Arc::new(compute_returning_seed_names(&arc, func));
        self.inner
            .write()
            .returning_seeds
            .entry(func)
            .or_insert(returning);
        arc
    }

    /// Probe the disk store for `func`, decode the payload, and hydrate
    /// the in-memory cache. Returns the cached graph on hit. `None`
    /// when there is no disk store, no entry for `func`, or the entry
    /// fails to decode (corrupt blob — falls through to recompute).
    fn try_hydrate_from_disk(&self, func: FuncId) -> Option<Arc<ValueFlowGraph>> {
        let reader = self.inner.read().disk.clone()?;
        let hit = reader.get(u64::from(func.raw())).ok().flatten()?;
        let pool = reader.string_pool().ok()?;
        let entry = decode_value_flow_entry(&hit.payload, &pool).ok()?;
        // The `ValueFlowGraph` itself can be tens of KB to MB on
        // large functions — that was the linear-growth source the
        // Redis OOM fix targeted, so the freshly decoded graph is
        // returned without inserting back into `inner.graphs`. The
        // `returning_seeds` set, however, is just function-local seed
        // names (a few entries, kilobytes at worst) and is the only
        // path through which `returning_seed_names()` can answer
        // without re-running the engine. Cache it so subsequent
        // queries don't repeat the decode + graph rebuild.
        let returning = Arc::new(entry.returning_seeds);
        self.inner
            .write()
            .returning_seeds
            .entry(func)
            .or_insert(returning);
        Some(Arc::new(entry.graph))
    }

    /// Set of seed names whose forward closure in `func`'s
    /// value-flow graph reaches a `Return` node in `func`.
    /// Materialised at graph-build time so compatibility clients can answer
    /// "does any of these seeds reach a return?" with a single set
    /// intersection instead of a per-seed forward-closure walk.
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
        // as a side effect (either from disk or from the engine) —
        // simplest way to keep both stores in sync.
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
    /// one-off callers; an explicit compatibility prewarm should use
    /// [`Self::prewarm_all_with_caches`] so the singleton accumulates.
    pub fn prewarm_all(&self, db: &AnalyzerDb) {
        let caches = InterTaintCaches::default();
        self.prewarm_all_with_caches(db, &caches);
    }

    /// Variant of [`Self::prewarm_all`] that fans out across the
    /// workspace using the caller's shared `InterTaintCaches`.
    /// Accumulating resolver answers across the prewarm fold means later
    /// compatibility queries reuse the same resolver state.
    ///
    /// In-memory variant: every computed graph stays resident in the
    /// in-memory map. Use [`Self::prewarm_to_disk`] when peak RAM
    /// matters — that variant streams entries directly into a
    /// fact-store file as they're produced and leaves the in-memory
    /// map empty so subsequent queries page in lazily.
    pub fn prewarm_all_with_caches(&self, db: &AnalyzerDb, caches: &InterTaintCaches) {
        let todo = self.functions_pending_prewarm(db);
        if todo.is_empty() {
            return;
        }
        // Build the canonical compiler graph as a distinct phase before the
        // parallel provenance projections. This retains top-level parallel
        // AST lowering and prevents sibling closures from contending with a
        // cold single-flight initializer inside the Rayon batch.
        let _compiler_idg = bonsai_taint::compiler_idg_service(db);
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

    /// Stream-and-write prewarm. Computes every callable function's
    /// graph in parallel, encodes each into the fact-store writer
    /// immediately (so peak RAM is bounded by the in-flight rayon
    /// chunk, not by the workspace), atomically replaces the sidecar
    /// at `path`, and opens the resulting file as the cache's disk
    /// store. After this call the in-memory map is empty; subsequent
    /// `graph_for` calls hydrate one entry at a time on demand.
    ///
    /// On encode/write error the cache is left untouched and the
    /// error is returned so callers can fall back to in-memory
    /// prewarm if disk is unavailable.
    pub fn prewarm_to_disk(
        &self,
        path: &Path,
        db: &AnalyzerDb,
        caches: &InterTaintCaches,
    ) -> std::io::Result<usize> {
        let todo = self.functions_pending_prewarm(db);
        if todo.is_empty() {
            // Even when there's nothing new to compute we still
            // open the existing sidecar (if any) so subsequent
            // queries hit disk. Treat absent file as "nothing on
            // disk" rather than as an error.
            if path.exists() {
                let _ = self.load_from_disk(path, db);
            }
            return Ok(0);
        }
        let _compiler_idg = bonsai_taint::compiler_idg_service(db);
        let (memory_entries, disk_reader): (Vec<ValueFlowMemoryEntry>, Option<Arc<FactStoreReader>>) = {
            let inner = self.inner.read();
            (
                inner
                    .graphs
                    .iter()
                    .map(|(&func, graph)| {
                        let returning = inner
                            .returning_seeds
                            .get(&func)
                            .cloned()
                            .unwrap_or_else(|| Arc::new(AHashSet::default()));
                        (func, graph.clone(), returning)
                    })
                    .collect(),
                inner.disk.clone(),
            )
        };
        // The channel-based writer takes `&self` for both `add` and
        // `intern`, so the rayon workers share the writer directly
        // without a Mutex wrapper. File I/O happens off the rayon hot
        // path on the writer's dedicated thread; intern serializes on a
        // small mutex internal to the writer.
        let writer = FactStoreWriter::create_with_capacity(
            path,
            VALUE_FLOW_TABLE_ID,
            value_flow_pipeline_hash(db, path),
            todo.len(),
            // Rough heuristics for capacity hints: ~512 bytes of
            // interned bytes and ~64 unique strings per function.
            // The writer grows past these if needed.
            todo.len().saturating_mul(512),
            todo.len().saturating_mul(64),
        )
        .map_err(map_factstore_io)?;
        let written_keys = std::sync::Mutex::new(AHashSet::<FuncId>::default());
        let write_error = std::sync::Mutex::new(None::<std::io::Error>);
        for (func, graph, returning) in memory_entries {
            let entry = ValueFlowEntry {
                graph: (*graph).clone(),
                returning_seeds: (*returning).clone(),
            };
            let payload = encode_value_flow_entry(&entry, &mut |s| writer.intern(s));
            writer
                .add_owned(u64::from(func.raw()), RESERVED_BODY_HASH, payload)
                .map_err(map_factstore_io)?;
            written_keys.lock().expect("written keys lock").insert(func);
        }
        todo.par_iter().for_each(|&f| {
            if write_error.lock().expect("write error lock").is_some() {
                return;
            }
            let graph = value_flow_for_function_with_caches(f, db, &InterTaintConfig::default(), caches);
            let returning = compute_returning_seed_names(&graph, f);
            let entry = ValueFlowEntry {
                graph,
                returning_seeds: returning,
            };
            let payload = encode_value_flow_entry(&entry, &mut |s| writer.intern(s));
            if let Err(err) = writer.add_owned(u64::from(f.raw()), RESERVED_BODY_HASH, payload) {
                let mut first_error = write_error.lock().expect("write error lock");
                if first_error.is_none() {
                    *first_error = Some(map_factstore_io(err));
                }
            } else {
                written_keys.lock().expect("written keys lock").insert(f);
            }
        });
        if let Some(error) = write_error.lock().expect("write error lock").take() {
            // Dropping the writer closes the bounded channel and joins its
            // worker without publishing the temporary sidecar.  Never turn a
            // partial parallel prewarm into a cache that looks complete.
            return Err(error);
        }
        if let Some(reader) = disk_reader {
            let pool = reader.string_pool().map_err(map_factstore_io)?;
            for item in reader.iter() {
                let (key, hit) = item.map_err(map_factstore_io)?;
                let func = FuncId::new(u32::try_from(key).map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "value-flow sidecar key out of FuncId u32 range",
                    )
                })?);
                if written_keys.lock().expect("written keys lock").contains(&func) {
                    continue;
                }
                let entry = decode_value_flow_entry(&hit.payload, &pool)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
                let payload = encode_value_flow_entry(&entry, &mut |s| writer.intern(s));
                writer
                    .add_owned(u64::from(func.raw()), RESERVED_BODY_HASH, payload)
                    .map_err(map_factstore_io)?;
                written_keys.lock().expect("written keys lock").insert(func);
            }
        }
        let written = writer.finish().map_err(map_factstore_io)?;
        let reader = FactStoreReader::open(path, VALUE_FLOW_TABLE_ID, value_flow_pipeline_hash(db, path))
            .map_err(map_factstore_io)?;
        let mut inner = self.inner.write();
        // Drop any stale in-memory entries; the disk store is the
        // single source of truth from here forward.
        inner.graphs.clear();
        inner.returning_seeds.clear();
        inner.disk = Some(Arc::new(reader));
        Ok(written)
    }

    /// Collect the FuncIds we still need to compute — every callable
    /// function whose graph isn't already resident in memory or on
    /// disk.
    fn functions_pending_prewarm(&self, db: &AnalyzerDb) -> Vec<FuncId> {
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
        let inner = self.inner.read();
        let in_memory: AHashSet<FuncId> = inner.graphs.keys().copied().collect();
        let disk = inner.disk.clone();
        drop(inner);
        funcs
            .into_iter()
            .filter(|f| {
                if in_memory.contains(f) {
                    return false;
                }
                if let Some(reader) = &disk {
                    if reader.get(u64::from(f.raw())).ok().flatten().is_some() {
                        return false;
                    }
                }
                true
            })
            .collect()
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

    /// Number of cached graphs across the in-memory map and any
    /// open disk store.
    ///
    /// Disk-backed entries that haven't been queried yet count
    /// toward this total — the cache's "size" is the union. When
    /// no disk store is open this collapses to the in-memory count.
    #[must_use]
    pub fn len(&self) -> usize {
        let inner = self.inner.read();
        let in_memory = inner.graphs.len();
        let on_disk = inner.disk.as_ref().map_or(0, |r| r.len());
        // A disk-resident entry that's been hydrated into the
        // in-memory map appears in both counts; subtract the overlap
        // so callers can use `len()` as a true "how many distinct
        // graphs are reachable" metric.
        let overlap = match inner.disk.as_ref() {
            Some(reader) => inner
                .graphs
                .keys()
                .filter(|f| reader.get(u64::from(f.raw())).ok().flatten().is_some())
                .count(),
            None => 0,
        };
        in_memory + on_disk - overlap
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        let inner = self.inner.read();
        let mem_empty = inner.graphs.is_empty();
        let disk_empty = inner.disk.as_ref().is_none_or(|r| r.is_empty());
        mem_empty && disk_empty
    }

    /// Drop every cached entry and close any open disk store.
    /// Triggered by file edits via [`crate::Workspace::ingest_dir`]
    /// — the on-disk file is left in place for the next prewarm to
    /// overwrite atomically.
    pub fn clear(&self) {
        let mut inner = self.inner.write();
        inner.graphs.clear();
        inner.returning_seeds.clear();
        inner.disk = None;
    }

    /// Conventional sidecar path under `workspace_root/.bonsai/`.
    /// v3 uses the `.factstore` extension to make the format change
    /// obvious in directory listings; pre-v3 `.bin` files are not
    /// recognised by the new reader and are ignored on load.
    #[must_use]
    pub fn sidecar_path(workspace_root: &Path) -> PathBuf {
        workspace_bonsai_dir(workspace_root).join(format!("value_flow.v{VALUE_FLOW_CACHE_VERSION}.factstore"))
    }

    /// Serialize all in-memory + disk-backed graphs to a fact-store
    /// file at `path`, atomic-rename style. The new file becomes the
    /// cache's disk store on success so subsequent queries page from
    /// disk instead of holding the just-written entries in memory.
    pub fn save_to_disk(&self, path: &Path, db: &AnalyzerDb) -> std::io::Result<()> {
        let inner = self.inner.read();
        let writer = FactStoreWriter::create_with_capacity(
            path,
            VALUE_FLOW_TABLE_ID,
            value_flow_pipeline_hash(db, path),
            inner.graphs.len(),
            inner.graphs.len().saturating_mul(512),
            inner.graphs.len().saturating_mul(64),
        )
        .map_err(map_factstore_io)?;
        // First, fold every in-memory entry into the writer. We
        // clone the maps' entries to plain owned `ValueFlowEntry`s
        // because the encoder expects owned data; the clone is cheap
        // (Arc + a HashSet clone) and frees us from juggling lifetimes.
        let mem_entries: Vec<(FuncId, Arc<ValueFlowGraph>, Arc<AHashSet<String>>)> = inner
            .graphs
            .iter()
            .map(|(f, g)| {
                let returning = inner
                    .returning_seeds
                    .get(f)
                    .cloned()
                    .unwrap_or_else(|| Arc::new(AHashSet::default()));
                (*f, g.clone(), returning)
            })
            .collect();
        let disk_reader = inner.disk.clone();
        drop(inner);
        let mut written_keys: AHashSet<FuncId> = AHashSet::with_capacity(mem_entries.len());
        for (f, graph, returning) in mem_entries {
            let entry = ValueFlowEntry {
                graph: (*graph).clone(),
                returning_seeds: (*returning).clone(),
            };
            let payload = encode_value_flow_entry(&entry, &mut |s| writer.intern(s));
            writer
                .add_owned(u64::from(f.raw()), RESERVED_BODY_HASH, payload)
                .map_err(map_factstore_io)?;
            written_keys.insert(f);
        }
        // Then any disk-backed entries the in-memory map didn't cover.
        // Decode each one through the existing pool and re-encode
        // through the new writer's pool — string ids aren't portable
        // across files.
        if let Some(reader) = disk_reader {
            let pool = reader.string_pool().map_err(map_factstore_io)?;
            for item in reader.iter() {
                let (key, hit) = item.map_err(map_factstore_io)?;
                let func = FuncId::new(u32::try_from(key).map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "value-flow sidecar key out of FuncId u32 range",
                    )
                })?);
                if written_keys.contains(&func) {
                    continue;
                }
                let entry = decode_value_flow_entry(&hit.payload, &pool)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
                let payload = encode_value_flow_entry(&entry, &mut |s| writer.intern(s));
                writer
                    .add_owned(u64::from(func.raw()), RESERVED_BODY_HASH, payload)
                    .map_err(map_factstore_io)?;
                written_keys.insert(func);
            }
        }
        writer.finish().map_err(map_factstore_io)?;
        // We deliberately do NOT mutate the in-memory map here.
        // `save_to_disk` is the "persist current state" call — its
        // contract is that the cache continues to behave the same in
        // memory after a save. The fact-store file just gives a
        // future process (or a future `load_from_disk` on this
        // process) a way to skip the rebuild.
        //
        // The bounded-RAM mode is reached via `prewarm_to_disk`,
        // which streams entries to disk as they're computed and
        // intentionally leaves the in-memory map empty so subsequent
        // queries page lazily.
        Ok(())
    }

    /// Load from a fact-store file written by [`Self::save_to_disk`]
    /// (or [`Self::prewarm_to_disk`]). Returns the number of entries
    /// the file contains; the cache then probes them lazily on
    /// `graph_for_with_caches`.
    ///
    /// Non-existent file returns `Ok(0)` (nothing to load, not an
    /// error). Version / pipeline-hash mismatch and corrupt files
    /// return `Ok(0)` after a `tracing::warn!` — the next prewarm
    /// will overwrite the file.
    pub fn load_from_disk(&self, path: &Path, db: &AnalyzerDb) -> std::io::Result<usize> {
        if !path.exists() {
            return Ok(0);
        }
        let reader =
            match FactStoreReader::open(path, VALUE_FLOW_TABLE_ID, value_flow_pipeline_hash(db, path)) {
                Ok(reader) => reader,
                Err(err) => {
                    tracing::warn!(
                        path = %path.display(),
                        error = %err,
                        "ignoring stale or corrupt value-flow sidecar"
                    );
                    discard_stale_factstore_sidecar(path, &err);
                    return Ok(0);
                }
            };
        let entries = reader.len();
        let mut inner = self.inner.write();
        inner.disk = Some(Arc::new(reader));
        Ok(entries)
    }

    /// Validate that a value-flow factstore is structurally readable and
    /// carries the expected table id. Freshness is checked separately by
    /// cache manifests and workspace fingerprints.
    pub fn validate_sidecar_file(path: &Path) -> std::io::Result<usize> {
        let reader = FactStoreReader::open_relaxed(path).map_err(map_factstore_io)?;
        if reader.header().table_id != VALUE_FLOW_TABLE_ID {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "value-flow factstore table id mismatch: file={} expected={}",
                    reader.header().table_id,
                    VALUE_FLOW_TABLE_ID
                ),
            ));
        }
        Ok(reader.len())
    }

    /// Validate a value-flow factstore against the exact source path/hash set
    /// currently on disk. This mirrors [`Self::load_from_disk`] without
    /// requiring a parsed [`AnalyzerDb`].
    pub fn validate_sidecar_file_with_source_fingerprints<I, P>(
        path: &Path,
        fingerprints: I,
    ) -> std::io::Result<usize>
    where
        I: IntoIterator<Item = (P, u64)>,
        P: AsRef<Path>,
    {
        let content = workspace_content_fingerprint_from_paths(fingerprints);
        let reader = FactStoreReader::open(
            path,
            VALUE_FLOW_TABLE_ID,
            value_flow_pipeline_hash_for_content(content, path),
        )
        .map_err(map_factstore_io)?;
        Ok(reader.len())
    }

    /// In-memory snapshot of the cache for tests, daemon checkpoints,
    /// and SDK consumers that want to ship the cache shape across
    /// process boundaries without going through disk. Includes both
    /// in-memory and disk-backed entries; the latter are decoded
    /// inline so the snapshot is fully self-contained. Mirrors
    /// `DataFlowCache::snapshot`.
    #[must_use]
    pub fn snapshot(&self) -> SerializableValueFlowSnapshot {
        let inner = self.inner.read();
        let mut entries: Vec<SerializableValueFlowEntry> = inner
            .graphs
            .iter()
            .map(|(func, graph)| SerializableValueFlowEntry {
                func_raw: func.raw(),
                graph: (**graph).clone(),
            })
            .collect();
        let disk = inner.disk.clone();
        let included: AHashSet<u32> = entries.iter().map(|e| e.func_raw).collect();
        drop(inner);
        if let Some(reader) = disk {
            if let Ok(pool) = reader.string_pool() {
                for item in reader.iter() {
                    let Ok((key, hit)) = item else { continue };
                    let Ok(func_raw) = u32::try_from(key) else {
                        continue;
                    };
                    if included.contains(&func_raw) {
                        continue;
                    }
                    let Ok(entry) = decode_value_flow_entry(&hit.payload, &pool) else {
                        continue;
                    };
                    entries.push(SerializableValueFlowEntry {
                        func_raw,
                        graph: entry.graph,
                    });
                }
            }
        }
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
        if reach
            .iter()
            .any(|n| n.func == func && matches!(n.kind, ValueFlowNodeKind::Return))
        {
            out.insert(origin.value_text.clone());
        }
    }
    out
}

/// Funnel `bonsai_factstore::FactStoreError` into `std::io::Error`
/// so callers don't pivot on the inner error variant. The fact-store
/// errors that bubble up here are I/O-shaped (truncation, bad magic,
/// pipeline mismatch) and treating them as opaque `Other` is the
/// right granularity for sidecar consumers.
fn map_factstore_io(err: bonsai_factstore::FactStoreError) -> std::io::Error {
    match err {
        bonsai_factstore::FactStoreError::Io(e) => e,
        other => std::io::Error::other(other),
    }
}

/// On-disk snapshot. Round-trips via Serde.
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
#[path = "value_flow_tests.rs"]
mod tests;
