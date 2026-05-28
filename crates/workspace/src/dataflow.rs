//! Workspace-wide taint-connected data-flow cache.
//!
//! Built lazily by query paths or explicitly by prewarm/export/audit
//! commands. For each requested function, runs
//! [`bonsai_taint::taint_facts_for_entry`] once and caches the result
//! so downstream queries (inspect, export, security) can reuse exact
//! facts without making the default structural index solve every entry.
//!
//! Keyed by [`FuncId`]; built in parallel via rayon (one worker per
//! function, bounded by `InterTaintConfig::budget`); incremental
//! invalidation on file edits via content hash + matcher policy
//! fingerprint; persistable via [`DataFlowCache::save_to_disk`] for
//! near-instant warm reopens.

use crate::cache_fingerprint::{
    dependency_metadata_fingerprint_for_sidecar, discard_stale_factstore_sidecar,
    workspace_content_fingerprint,
};
use ahash::{AHashMap, AHashSet};
use bonsai_common::{workspace_bonsai_dir, FileId, FuncId, SymbolId, MATCHER_POLICY_FINGERPRINT};
use bonsai_db::AnalyzerDb;
use bonsai_lang_api::DeclKind;
use bonsai_taint::{
    taint_facts_and_graph_for_entry, taint_facts_and_graph_for_entry_with_caches, EntryTaintGraph,
    InterTaintCaches, KindedTokens, TokenSet,
};
use parking_lot::RwLock;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::{
    ffi::OsString,
    path::{Path, PathBuf},
    process::{self, Command, Stdio},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};

/// Monotonic bump. Increment every time the on-disk format changes
/// (shape of `KindedTokens`, serialisation layout, propagation
/// semantics) so old sidecars are rejected on open.
// v28 (2026-05-27): IDG seeding / side-effect changes (transfer.rs
// method-receiver-base source exemption + container-input span
// containment, service.rs return-position source-seeding fallback) and
// adapter member synthesis alter propagated taint facts.
pub const DATAFLOW_CACHE_VERSION: u32 = 28;
static SIDECAR_TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

type DataFlowMemoryEntry = (FuncId, Arc<KindedTokens>, Arc<EntryTaintGraph>, AHashSet<FileId>);

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SnapshotFile {
    pub path: String,
    pub file_hash: u64,
}

/// One entry in a persisted snapshot. Content-addressable: keyed
/// by the function's (name, file table index) so that a reload into a
/// freshly-indexed workspace — where the raw `SymbolId`/`FuncId`
/// counter allocation may have landed on different numeric ids —
/// still correctly re-associates each entry with the right function.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SnapshotEntry {
    /// Function's display name (`Decl::name`).
    pub func_name: String,
    /// Index into [`SerializableSnapshot::files`] for the declaring
    /// file. Interning file paths here avoids repeating long paths in
    /// every function + dependency entry on large projects.
    pub file_index: u32,
    /// Byte offset of the function's name span inside the declaring file —
    /// disambiguates overloads / same-name same-file functions.
    pub name_span_start: u64,
    /// Transitive downstream files that can affect this entry's
    /// interprocedural taint facts. An unchanged entry file can still
    /// become stale when a callee file changes, so reload validation
    /// checks every dependency hash. Values are indexes into
    /// [`SerializableSnapshot::files`].
    pub dependencies: Vec<u32>,
    /// The cached taint facts themselves.
    pub facts: KindedTokens,
    /// Structured semantic taint graph for this entry.
    #[serde(default)]
    pub graph: EntryTaintGraph,
}

/// Serialisable snapshot — round-trips via `bincode`. Every entry
/// carries enough identity to find its function in a
/// freshly-reopened workspace.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SerializableSnapshot {
    pub version: u32,
    /// Compatibility fingerprint for older sidecars that carried a
    /// sanitizer profile. Current propagation is sanitizer-neutral.
    #[serde(default)]
    pub sanitizer_fingerprint: u128,
    /// Matcher policy fingerprint. Security rule matching is applied
    /// after graph load, but the cached graph is consumed together
    /// with matcher classifications; stale matcher policy must force
    /// a sidecar miss.
    #[serde(default)]
    pub matcher_policy_fingerprint: u128,
    /// Dependency metadata fingerprint for manifests / lockfiles
    /// that can influence import and call resolution outside the
    /// source file set.
    #[serde(default)]
    pub dependency_metadata_fingerprint: u64,
    /// Compatibility field for older sidecars. Current snapshots
    /// always persist an empty sanitizer set because sanitizers are
    /// report evidence, not graph inputs.
    #[serde(default)]
    pub sanitizer_tokens: Vec<String>,
    /// Interned file path + content-hash table. Entries and dependency
    /// lists store compact indexes into this table instead of repeating
    /// absolute path strings thousands of times.
    #[serde(default)]
    pub files: Vec<SnapshotFile>,
    pub entries: Vec<SnapshotEntry>,
}

/// Caller-defined table id for the dataflow fact-store sidecar.
/// Distinguishes a dataflow fact-store from a value-flow one when
/// they share the `.bonsai/` directory.
const DATAFLOW_FACTSTORE_TABLE_ID: u32 = 2;

/// Pipeline-hash field in the factstore header. Folds the matcher
/// policy fingerprint into 64 bits and the current workspace content
/// fingerprint so a matcher policy or source-tree change invalidates
/// the cache file before any stale FuncId-keyed entries can hydrate.
fn dataflow_pipeline_hash(db: &AnalyzerDb, sidecar_path: &Path) -> u64 {
    let raw = MATCHER_POLICY_FINGERPRINT;
    (raw as u64)
        ^ ((raw >> 64) as u64)
        ^ u64::from(DATAFLOW_CACHE_VERSION)
        ^ workspace_content_fingerprint(db)
        ^ dependency_metadata_fingerprint_for_sidecar(sidecar_path)
        ^ crate::build_fingerprint_hash()
}

/// Thread-safe per-function taint-facts cache. One instance per
/// `Workspace`; owned by [`crate::Workspace`].
#[derive(Default, Debug)]
pub struct DataFlowCache {
    inner: RwLock<Inner>,
    /// Lazy-built workspace-wide resolved call graph, shared across
    /// `prewarm_all` / `snapshot` / `dependency_files_for_db` so the
    /// graph is constructed at most once per cache lifetime instead
    /// of three times. Cleared on `invalidate_file`.
    cached_call_graph: RwLock<Option<Arc<bonsai_callgraph::ResolvedCallGraph>>>,
    /// Optional shared `InterTaintCaches` seeded by the workspace at
    /// open time. When present, prewarm + lazy-fault paths thread
    /// it into `taint_facts_and_graph_for_entry_with_caches` so the
    /// engine's resolver memo / alias maps / function summaries
    /// accumulate across runs.
    seeded_inter_taint: RwLock<Option<Arc<InterTaintCaches>>>,
    /// Optional disk-backed source of truth, populated by
    /// [`DataFlowCache::prewarm_to_disk`] or
    /// [`DataFlowCache::load_from_disk`]. When present, lookups that
    /// miss the in-memory map probe the fact store before falling
    /// through to the engine. Held in an `Arc` so look-up paths can
    /// drop the inner read-lock before doing the disk seek.
    disk: RwLock<Option<Arc<bonsai_factstore::FactStoreReader>>>,
}

#[derive(Default, Debug)]
struct Inner {
    /// Precomputed taint facts per function. Populated by
    /// [`DataFlowCache::prewarm_all`]; queried by
    /// [`DataFlowCache::facts_for`].
    facts: AHashMap<FuncId, Arc<KindedTokens>>,
    /// Structured per-entry taint graph built at index time.
    graphs: AHashMap<FuncId, Arc<EntryTaintGraph>>,
    /// Transitive file dependencies for each cached function entry.
    /// Includes the declaring file and every downstream callee file
    /// reached through the resolved call graph.
    dependencies: AHashMap<FuncId, AHashSet<FileId>>,
    /// Per-file `(file, content_hash)` snapshot so we can detect a
    /// stale file on reopen and invalidate only its dependents.
    file_hashes: AHashMap<FileId, u64>,
    /// `true` once [`DataFlowCache::prewarm_all`] has completed at
    /// least once. Tells callers the graph is ready; on-demand
    /// `facts_for` still works before prewarm, it just pays the
    /// interprocedural cost per first access.
    prewarmed: bool,
    /// Compatibility fingerprint for the canonical graph profile.
    sanitizer_fingerprint: u128,
    /// Compatibility token set. Kept empty because sanitizer names do
    /// not alter cached facts or graphs.
    sanitizer_tokens: Arc<TokenSet>,
    /// Matcher policy fingerprint used for the current cache profile.
    matcher_policy_fingerprint: u128,
}

impl DataFlowCache {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Lazy-built per-cache resolved call graph. Built on first
    /// access, dropped by `invalidate_file`. Shared across the
    /// internal prewarm / snapshot / dependency-walk paths so the
    /// graph is constructed at most once per cache lifetime.
    fn call_graph_for(&self, db: &AnalyzerDb) -> Arc<bonsai_callgraph::ResolvedCallGraph> {
        // Drop the read guard before any potential write upgrade —
        // parking_lot RwLocks are non-reentrant. (See B1 hazard +
        // design-patterns.mdx §13a.)
        let cached = self.cached_call_graph.read().as_ref().cloned();
        if let Some(hit) = cached {
            return hit;
        }
        let built = Arc::new(snapshot_call_graph(db));
        let mut slot = self.cached_call_graph.write();
        if let Some(existing) = slot.as_ref().cloned() {
            return existing;
        }
        *slot = Some(built.clone());
        built
    }

    /// Inject a workspace-cached call graph as the seed for this
    /// cache. Workspace-level callers that already hold one (via
    /// `Workspace::cached_resolved_call_graph`) call this once at
    /// open time so the dataflow cache skips a second build.
    pub fn seed_call_graph(&self, graph: Arc<bonsai_callgraph::ResolvedCallGraph>) {
        *self.cached_call_graph.write() = Some(graph);
    }

    /// Inject the workspace-wide `InterTaintCaches` singleton so the
    /// dataflow prewarm + lazy faults share the engine's resolver
    /// memo, alias maps, and function summaries with subsequent
    /// security-analysis / value-flow / inspect runs. The workspace
    /// calls this once at open time.
    pub fn seed_inter_taint_caches(&self, caches: Arc<InterTaintCaches>) {
        *self.seeded_inter_taint.write() = Some(caches);
    }

    /// Compute taint facts + graph for `func`, threading the seeded
    /// `InterTaintCaches` when present. Falls through to a fresh
    /// per-call `InterTaintCaches::default()` for standalone
    /// callers (tests, one-shot SDK consumers).
    fn compute_facts_and_graph(&self, func: FuncId, db: &AnalyzerDb) -> (KindedTokens, EntryTaintGraph) {
        let seeded = self.seeded_inter_taint.read().clone();
        match seeded {
            Some(caches) => {
                taint_facts_and_graph_for_entry_with_caches(func, db, &TokenSet::default(), &caches)
            }
            None => taint_facts_and_graph_for_entry(func, db, &TokenSet::default()),
        }
    }

    /// Get the cached taint facts for a function, computing them on
    /// demand if not cached. Returns `Arc<KindedTokens>` so multiple
    /// concurrent readers share one allocation.
    pub fn facts_for(&self, func: FuncId, db: &AnalyzerDb) -> Arc<KindedTokens> {
        self.facts_for_with_sanitizers(func, db, &TokenSet::default())
    }

    /// Compatibility entry point for older callers. Sanitizers are
    /// classification evidence and do not alter propagation, so this
    /// ignores the supplied set and uses the canonical graph cache.
    pub fn facts_for_with_sanitizers(
        &self,
        func: FuncId,
        db: &AnalyzerDb,
        _sanitizers: &TokenSet,
    ) -> Arc<KindedTokens> {
        let cached = self.inner.read().facts.get(&func).cloned();
        if let Some(hit) = cached {
            return hit;
        }
        if let Some((facts, _graph)) = self.try_hydrate_from_disk(func) {
            return facts;
        }
        let (facts, graph) = self.compute_facts_and_graph(func, db);
        let dependencies = self.dependency_files_via_cache(func, db);
        let computed = Arc::new(facts);
        let graph = Arc::new(graph);
        let mut inner = self.inner.write();
        if inner.sanitizer_fingerprint == 0 {
            inner.sanitizer_fingerprint = EMPTY_SANITIZER_FINGERPRINT;
        }
        if inner.matcher_policy_fingerprint == 0 {
            inner.matcher_policy_fingerprint = MATCHER_POLICY_FINGERPRINT;
        }
        inner.facts.insert(func, computed.clone());
        inner.graphs.insert(func, graph);
        inner.dependencies.insert(func, dependencies);
        computed
    }

    /// Probe the disk store for `func`, decode the payload, and
    /// hydrate the in-memory caches. Returns `(facts, graph)` on hit.
    /// `None` when there is no disk store, no entry for `func`, or the
    /// entry fails to decode (corrupt blob — caller falls through to
    /// recompute via the engine).
    fn try_hydrate_from_disk(&self, func: FuncId) -> Option<(Arc<KindedTokens>, Arc<EntryTaintGraph>)> {
        let reader = self.disk.read().clone()?;
        let hit = reader.get(u64::from(func.raw())).ok().flatten()?;
        let entry = crate::dataflow_disk::decode(&hit.payload).ok()?;
        let dependencies = entry.dependency_set();
        let facts = Arc::new(entry.facts);
        let graph = Arc::new(entry.graph);
        let mut inner = self.inner.write();
        if inner.sanitizer_fingerprint == 0 {
            inner.sanitizer_fingerprint = EMPTY_SANITIZER_FINGERPRINT;
        }
        if inner.matcher_policy_fingerprint == 0 {
            inner.matcher_policy_fingerprint = MATCHER_POLICY_FINGERPRINT;
        }
        // `KindedTokens` and dependency sets are small (a few KB each)
        // and the snapshot() / save_to_disk() bincode round-trip relies
        // on `inner.facts` being populated, so we always cache those
        // back. `inner.graphs`, on the other hand, holds an
        // `Arc<EntryTaintGraph>` per function — those can be tens of
        // KB to MB on big functions and were the linear-growth source
        // that OOM'd Redis. Returning the freshly decoded graph
        // without inserting keeps the in-memory `graphs` map empty
        // post-prewarm: queries get a one-shot decoded `Arc` for the
        // duration of the consumer's borrow and disk holds the
        // canonical copy.
        let canonical_facts = inner.facts.entry(func).or_insert_with(|| facts).clone();
        inner.dependencies.entry(func).or_insert(dependencies);
        Some((canonical_facts, graph))
    }

    pub fn graph_for(&self, func: FuncId, db: &AnalyzerDb) -> Arc<EntryTaintGraph> {
        self.graph_for_with_sanitizers(func, db, &TokenSet::default())
    }

    /// Compatibility entry point for older callers. Sanitizers are
    /// classification evidence and do not alter propagation, so this
    /// ignores the supplied set and uses the canonical graph cache.
    pub fn graph_for_with_sanitizers(
        &self,
        func: FuncId,
        db: &AnalyzerDb,
        _sanitizers: &TokenSet,
    ) -> Arc<EntryTaintGraph> {
        let cached = self.inner.read().graphs.get(&func).cloned();
        if let Some(hit) = cached {
            return hit;
        }
        if let Some((_facts, graph)) = self.try_hydrate_from_disk(func) {
            return graph;
        }
        let (facts, graph) = self.compute_facts_and_graph(func, db);
        let dependencies = self.dependency_files_via_cache(func, db);
        let facts = Arc::new(facts);
        let graph = Arc::new(graph);
        let mut inner = self.inner.write();
        if inner.sanitizer_fingerprint == 0 {
            inner.sanitizer_fingerprint = EMPTY_SANITIZER_FINGERPRINT;
        }
        if inner.matcher_policy_fingerprint == 0 {
            inner.matcher_policy_fingerprint = MATCHER_POLICY_FINGERPRINT;
        }
        inner.facts.insert(func, facts);
        inner.graphs.insert(func, graph.clone());
        inner.dependencies.insert(func, dependencies);
        graph
    }

    /// Run the interprocedural pass for every function in the workspace
    /// in parallel and populate the cache. Safe to call more than once
    /// — second and later invocations skip already-cached entries.
    pub fn prewarm_all(&self, db: &AnalyzerDb) {
        self.prewarm_all_with_progress(db, |_| {});
    }

    /// Compatibility entry point. Sanitizers do not alter propagation.
    pub fn prewarm_all_with_sanitizers(&self, db: &AnalyzerDb, _sanitizers: &TokenSet) {
        self.prewarm_all_with_sanitizers_progress(db, &TokenSet::default(), |_| {});
    }

    /// How many functions the next `prewarm_all` call would actually
    /// compute (total callable decls minus already-cached entries).
    /// Callers use this to size a progress bar up front.
    pub fn pending_count(&self, db: &AnalyzerDb) -> usize {
        self.pending_count_with_sanitizers(db, &TokenSet::default())
    }

    /// Compatibility entry point. Sanitizers do not alter propagation.
    pub fn pending_count_with_sanitizers(&self, db: &AnalyzerDb, _sanitizers: &TokenSet) -> usize {
        let global = db.global_index();
        let inner = self.inner.read();
        let already: AHashSet<FuncId> = inner.facts.keys().copied().collect();
        drop(inner);
        let mut count: usize = 0;
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

    /// Like [`Self::prewarm_all`] but notifies `on_each_done` after
    /// every single function's taint facts are computed. The
    /// callback runs on the rayon worker that produced the entry
    /// and must be `Sync` (CLI wiring uses an atomic-backed
    /// `indicatif::ProgressBar`). Total work size is available up
    /// front via [`Self::pending_count`] for drawing a bar.
    ///
    /// The callback fires exactly once per cache entry populated by
    /// this call — already-cached entries do NOT emit progress.
    pub fn prewarm_all_with_progress<F>(&self, db: &AnalyzerDb, on_each_done: F)
    where
        F: Fn(FuncId) + Sync + Send,
    {
        self.prewarm_all_with_sanitizers_progress(db, &TokenSet::default(), on_each_done);
    }

    /// Compatibility entry point. Sanitizers do not alter propagation.
    pub fn prewarm_all_with_sanitizers_progress<F>(
        &self,
        db: &AnalyzerDb,
        _sanitizers: &TokenSet,
        on_each_done: F,
    ) where
        F: Fn(FuncId) + Sync + Send,
    {
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
        // Skip entries we already have facts for (warm-cache reopen).
        let already: AHashSet<FuncId> = self.inner.read().facts.keys().copied().collect();
        let todo: Vec<FuncId> = funcs.into_iter().filter(|f| !already.contains(f)).collect();
        if todo.is_empty() {
            self.inner.write().prewarmed = true;
            return;
        }
        let computed: Vec<(FuncId, Arc<KindedTokens>, Arc<EntryTaintGraph>)> = todo
            .par_iter()
            .map(|&f| {
                let (facts, graph) = self.compute_facts_and_graph(f, db);
                on_each_done(f);
                (f, Arc::new(facts), Arc::new(graph))
            })
            .collect();
        let call_graph = self.call_graph_for(db);
        let global = db.global_index();
        let mut inner = self.inner.write();
        for (f, facts, graph) in computed {
            inner.facts.insert(f, facts);
            inner.graphs.insert(f, graph);
            inner
                .dependencies
                .insert(f, dependency_files(f, &call_graph, &global));
        }
        inner.sanitizer_fingerprint = EMPTY_SANITIZER_FINGERPRINT;
        inner.sanitizer_tokens = Arc::new(TokenSet::default());
        inner.matcher_policy_fingerprint = MATCHER_POLICY_FINGERPRINT;
        // Record file content hashes so persisted reloads can detect
        // diffs across CLI processes. VFS versions reset in a fresh
        // process and are only valid for live edit invalidation.
        for file in db.vfs().all_files() {
            if let Ok(snap) = db.vfs().snapshot(file) {
                inner.file_hashes.insert(file, content_hash(snap.text.as_bytes()));
            }
        }
        inner.prewarmed = true;
    }

    /// Stream-and-write prewarm. Computes every callable function's
    /// facts + graph in parallel, encodes each into a fact-store
    /// writer immediately so peak RAM is bounded by the in-flight
    /// rayon chunk rather than the workspace size, atomically
    /// replaces the sidecar at `path`, and opens the resulting file
    /// as the cache's disk store. After this call the in-memory
    /// caches are empty; subsequent `facts_for` / `graph_for` calls
    /// hydrate one entry at a time on demand.
    pub fn prewarm_to_disk<F>(&self, path: &Path, db: &AnalyzerDb, on_each_done: F) -> std::io::Result<usize>
    where
        F: Fn(FuncId) + Sync + Send,
    {
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
        // Skip entries already on disk or in memory, but forward-port
        // those entries into the replacement factstore below. The
        // writer atomically replaces `path`; treating cached entries as
        // "no work" without copying them would make each partial
        // prewarm shrink the warm sidecar and force repeated analysis.
        let (already, memory_entries): (AHashSet<FuncId>, Vec<DataFlowMemoryEntry>) = {
            let inner = self.inner.read();
            (
                inner.facts.keys().copied().collect(),
                inner
                    .facts
                    .iter()
                    .filter_map(|(&func, facts)| {
                        let graph = inner.graphs.get(&func)?.clone();
                        let dependencies = inner.dependencies.get(&func).cloned().unwrap_or_default();
                        Some((func, facts.clone(), graph, dependencies))
                    })
                    .collect(),
            )
        };
        let disk_clone = self.disk.read().clone();
        let todo: Vec<FuncId> = funcs
            .into_iter()
            .filter(|f| {
                if already.contains(f) {
                    return false;
                }
                if let Some(reader) = &disk_clone {
                    if reader.get(u64::from(f.raw())).ok().flatten().is_some() {
                        return false;
                    }
                }
                true
            })
            .collect();
        if todo.is_empty() {
            // Open the existing sidecar if any so subsequent queries
            // hit disk; treat absent file as "nothing on disk."
            if path.exists() {
                let _ = self.load_factstore_sidecar(path, db);
            }
            return Ok(0);
        }
        // Channel-based writer: workers push entries to a queue
        // drained by a dedicated I/O thread, so file writes never
        // block the rayon worker pool.
        let writer = bonsai_factstore::FactStoreWriter::create_with_capacity(
            path,
            DATAFLOW_FACTSTORE_TABLE_ID,
            dataflow_pipeline_hash(db, path),
            todo.len(),
            todo.len().saturating_mul(1024),
            todo.len().saturating_mul(64),
        )
        .map_err(map_factstore_io)?;
        let call_graph = self.call_graph_for(db);
        let global_for_deps = db.global_index();
        let written_keys = std::sync::Mutex::new(AHashSet::<u64>::default());
        for (func, facts, graph, dependencies) in memory_entries {
            let entry = crate::dataflow_disk::DataFlowEntry::from_owned(
                (*facts).clone(),
                (*graph).clone(),
                dependencies,
            );
            let payload = crate::dataflow_disk::encode(&entry);
            let key = u64::from(func.raw());
            writer.add(key, 0, &payload).map_err(map_factstore_io)?;
            written_keys.lock().expect("written keys lock").insert(key);
        }
        todo.par_iter().for_each(|&f| {
            let (facts, graph) = self.compute_facts_and_graph(f, db);
            let dependencies = dependency_files(f, &call_graph, &global_for_deps);
            let entry = crate::dataflow_disk::DataFlowEntry::from_owned(facts, graph, dependencies);
            let payload = crate::dataflow_disk::encode(&entry);
            let key = u64::from(f.raw());
            if let Err(err) = writer.add(key, 0, &payload) {
                tracing::warn!(error = %err, "dataflow factstore add failed");
            } else {
                written_keys.lock().expect("written keys lock").insert(key);
            }
            on_each_done(f);
        });
        if let Some(reader) = disk_clone {
            for item in reader.iter() {
                let (key, hit) = item.map_err(map_factstore_io)?;
                if written_keys.lock().expect("written keys lock").contains(&key) {
                    continue;
                }
                writer
                    .add(key, hit.body_hash, &hit.payload)
                    .map_err(map_factstore_io)?;
                written_keys.lock().expect("written keys lock").insert(key);
            }
        }
        let written = writer.finish().map_err(map_factstore_io)?;
        let reader = bonsai_factstore::FactStoreReader::open(
            path,
            DATAFLOW_FACTSTORE_TABLE_ID,
            dataflow_pipeline_hash(db, path),
        )
        .map_err(map_factstore_io)?;
        // Drop in-memory state and swap in the disk store.
        let mut inner = self.inner.write();
        inner.facts.clear();
        inner.graphs.clear();
        inner.dependencies.clear();
        // Record file content hashes so reload validation works the
        // same as the legacy bincode path.
        for file in db.vfs().all_files() {
            if let Ok(snap) = db.vfs().snapshot(file) {
                inner.file_hashes.insert(file, content_hash(snap.text.as_bytes()));
            }
        }
        inner.sanitizer_fingerprint = EMPTY_SANITIZER_FINGERPRINT;
        inner.sanitizer_tokens = Arc::new(TokenSet::default());
        inner.matcher_policy_fingerprint = MATCHER_POLICY_FINGERPRINT;
        inner.prewarmed = true;
        drop(inner);
        *self.disk.write() = Some(Arc::new(reader));
        Ok(written)
    }

    /// Drop facts for every function declared in `file`, plus every
    /// cached function whose transitive dependency set includes
    /// `file`. Entries without dependency metadata are treated as
    /// stale so older live caches fail closed.
    pub fn invalidate_file(&self, file: FileId) {
        // Drop the cached resolved call graph: a file edit may have
        // added/removed/renamed callees, which would silently poison
        // every dependency walk that consumed the stale graph.
        *self.cached_call_graph.write() = None;
        // The factstore sidecar is immutable and was opened against
        // the pre-edit workspace fingerprint. Keep unaffected
        // in-memory entries below, but never hydrate from disk after a
        // live edit because the header cannot be revalidated without
        // reopening against the new workspace state.
        *self.disk.write() = None;
        let mut inner = self.inner.write();
        let stale: AHashSet<FuncId> = inner
            .facts
            .keys()
            .copied()
            .filter(|func| {
                inner
                    .dependencies
                    .get(func)
                    .is_none_or(|dependencies| dependencies.contains(&file))
            })
            .collect();
        if stale.is_empty() {
            inner.file_hashes.remove(&file);
            return;
        }
        for func in stale {
            inner.facts.remove(&func);
            inner.graphs.remove(&func);
            inner.dependencies.remove(&func);
        }
        inner.file_hashes.remove(&file);
        inner.prewarmed = false;
    }

    /// `true` once [`Self::prewarm_all`] has populated the cache for
    /// the current workspace snapshot.
    pub fn is_prewarmed(&self) -> bool {
        self.inner.read().prewarmed
    }

    /// Number of cached entries across in-memory and disk-backed
    /// stores. Handy for tests + the `open_with` stats printout.
    pub fn len(&self) -> usize {
        let in_memory = self.inner.read().facts.len();
        let on_disk = self.disk.read().as_ref().map_or(0, |r| r.len());
        // Disk-resident entries that have been hydrated into the
        // in-memory map appear in both counts; subtract the overlap
        // for a true "distinct entries reachable" metric.
        let overlap = match self.disk.read().as_ref() {
            Some(reader) => self
                .inner
                .read()
                .facts
                .keys()
                .filter(|f| reader.get(u64::from(f.raw())).ok().flatten().is_some())
                .count(),
            None => 0,
        };
        in_memory + on_disk - overlap
    }

    pub fn is_empty(&self) -> bool {
        let mem_empty = self.inner.read().facts.is_empty();
        let disk_empty = self.disk.read().as_ref().is_none_or(|r| r.is_empty());
        mem_empty && disk_empty
    }

    /// Serialise the cache to a `bincode`-compatible snapshot. Each
    /// entry carries `(func_name, file_index, name_span_start)`
    /// so a later `load_snapshot` can map it back to the right
    /// function even if `SymbolId`/`FuncId` counters land on
    /// different numbers during a fresh index.
    pub fn snapshot(&self, db: &AnalyzerDb) -> SerializableSnapshot {
        let call_graph = self.call_graph_for(db);
        // Hydrate every disk-backed entry into the in-memory caches
        // before iterating below. The streaming prewarm path
        // (`prewarm_to_disk`) clears in-memory facts after writing
        // the factstore sidecar, so without this the bincode v2.bin
        // snapshot would be empty even though the v3.factstore
        // sidecar holds the data. Idempotent: a hot in-memory hit
        // skips the disk seek.
        if self.disk.read().is_some() {
            let global_pre = db.global_index();
            for file in db.vfs().all_files() {
                for decl in global_pre.functions_in(file) {
                    let func = FuncId::new(decl.symbol.raw());
                    let already_hot = self.inner.read().facts.contains_key(&func);
                    if !already_hot {
                        let _ = self.try_hydrate_from_disk(func);
                    }
                }
            }
        }
        let inner = self.inner.read();
        let global = db.global_index();
        let file_hashes = current_file_hashes(db);
        let mut snapshot_files = Vec::new();
        let mut file_to_snapshot_index: AHashMap<FileId, u32> = AHashMap::new();
        for file in db.vfs().all_files() {
            let Ok(path) = db.vfs().path(file) else {
                continue;
            };
            let Some(file_hash) = file_hashes.get(&file).copied() else {
                continue;
            };
            let path = path.display().to_string();
            if path.is_empty() {
                continue;
            }
            let Ok(idx) = u32::try_from(snapshot_files.len()) else {
                continue;
            };
            file_to_snapshot_index.insert(file, idx);
            snapshot_files.push(SnapshotFile { path, file_hash });
        }
        let mut entries: Vec<SnapshotEntry> = Vec::with_capacity(inner.facts.len());
        for (func, facts) in inner.facts.iter() {
            let Some(decl) = global.decl_of(SymbolId::new(func.raw())) else {
                continue;
            };
            let Some(file) = global.declaring_file(decl.symbol) else {
                continue;
            };
            let Some(&file_index) = file_to_snapshot_index.get(&file) else {
                continue;
            };
            let mut dependencies = inner
                .dependencies
                .get(func)
                .cloned()
                .unwrap_or_else(|| dependency_files(*func, &call_graph, &global))
                .into_iter()
                .filter_map(|dep_file| file_to_snapshot_index.get(&dep_file).copied())
                .collect::<Vec<_>>();
            dependencies.sort_unstable();
            dependencies.dedup();
            entries.push(SnapshotEntry {
                func_name: decl.name.clone(),
                file_index,
                name_span_start: decl.name_span.start,
                dependencies,
                facts: (**facts).clone(),
                graph: inner.graphs.get(func).map(|g| (**g).clone()).unwrap_or_default(),
            });
        }
        // Sort entries deterministically so `bincode::serialize`
        // produces identical bytes across runs with identical
        // workspace state. Without this `inner.facts.iter()`
        // (AHashMap) iterates in random order and the on-disk
        // sidecar isn't content-addressable.
        entries.sort_unstable_by(|a, b| {
            (a.file_index, a.name_span_start, a.func_name.as_str()).cmp(&(
                b.file_index,
                b.name_span_start,
                b.func_name.as_str(),
            ))
        });
        SerializableSnapshot {
            version: DATAFLOW_CACHE_VERSION,
            sanitizer_fingerprint: EMPTY_SANITIZER_FINGERPRINT,
            matcher_policy_fingerprint: MATCHER_POLICY_FINGERPRINT,
            dependency_metadata_fingerprint: 0,
            sanitizer_tokens: Vec::new(),
            files: snapshot_files,
            entries,
        }
    }

    /// Rehydrate from a snapshot, discarding any prior state. Each
    /// snapshot entry is matched against the CURRENT workspace by
    /// `(files[file_index].path, func_name, name_span_start)`. An entry survives
    /// only when:
    ///
    /// 1. The snapshot version matches [`DATAFLOW_CACHE_VERSION`].
    /// 2. A file with the same path exists in the workspace.
    /// 3. That file's current content hash matches the snapshot's
    ///    recorded `file_hash` (content unchanged).
    /// 4. A function with the same name + name-span-start exists in
    ///    that file's decl index — rejects same-name-different-function
    ///    collisions.
    ///
    /// Returns the number of entries that survived. Caller can
    /// follow up with [`Self::prewarm_all`] to backfill the rest.
    pub fn load_snapshot(&self, snap: SerializableSnapshot, db: &AnalyzerDb) -> usize {
        if snap.version != DATAFLOW_CACHE_VERSION {
            return 0;
        }
        if snap.matcher_policy_fingerprint != MATCHER_POLICY_FINGERPRINT {
            return 0;
        }
        let vfs = db.vfs();
        let global = db.global_index();

        // (path → (file_id, content_hash)). Path-based lookup handles the
        // case where the caller writes content under the same path
        // but into a fresh VFS (different numeric FileId).
        let path_to_file: AHashMap<String, (FileId, u64)> = vfs
            .all_files()
            .into_iter()
            .filter_map(|f| {
                let path = vfs.path(f).ok()?;
                let snap = vfs.snapshot(f).ok()?;
                Some((
                    path.display().to_string(),
                    (f, content_hash(snap.text.as_bytes())),
                ))
            })
            .collect();

        let snapshot_files: Vec<Option<(FileId, u64)>> = snap
            .files
            .iter()
            .map(|file| path_to_file.get(&file.path).copied())
            .collect();

        let mut surviving: usize = 0;
        let mut new_facts: AHashMap<FuncId, Arc<KindedTokens>> = AHashMap::new();
        let mut new_graphs: AHashMap<FuncId, Arc<EntryTaintGraph>> = AHashMap::new();
        let mut new_dependencies: AHashMap<FuncId, AHashSet<FileId>> = AHashMap::new();
        let mut kept_files: AHashMap<FileId, u64> = AHashMap::new();

        for entry in snap.entries {
            let Some(file_meta) = snapshot_files.get(entry.file_index as usize) else {
                continue; // malformed entry file index
            };
            let Some((file_id, current_hash)) = *file_meta else {
                continue; // file no longer in workspace
            };
            let Some(snapshot_file) = snap.files.get(entry.file_index as usize) else {
                continue;
            };
            if current_hash != snapshot_file.file_hash {
                continue; // file contents changed
            }
            if entry.dependencies.iter().any(|&dep_idx| {
                let Some(snapshot_dep) = snap.files.get(dep_idx as usize) else {
                    return true;
                };
                snapshot_files
                    .get(dep_idx as usize)
                    .and_then(|meta| *meta)
                    .is_none_or(|(_, current_dep_hash)| current_dep_hash != snapshot_dep.file_hash)
            }) {
                continue; // downstream dependency changed
            }
            // Find the function in the current decl index by matching
            // name + name-span-start. Span-start disambiguates overloads
            // of the same name within a file.
            let matching_func: Option<FuncId> = global
                .decls_in(file_id)
                .iter()
                .find(|d| {
                    d.name == entry.func_name
                        && d.name_span.start == entry.name_span_start
                        && matches!(
                            d.kind,
                            bonsai_lang_api::DeclKind::Function
                                | bonsai_lang_api::DeclKind::Method
                                | bonsai_lang_api::DeclKind::Constructor
                        )
                })
                .map(|d| FuncId::new(d.symbol.raw()));
            let Some(func) = matching_func else {
                continue; // function gone or moved
            };
            let dependencies = entry
                .dependencies
                .iter()
                .filter_map(|&dep_idx| {
                    snapshot_files
                        .get(dep_idx as usize)
                        .and_then(|meta| meta.map(|(file, _)| file))
                })
                .collect::<AHashSet<_>>();
            new_facts.insert(func, Arc::new(entry.facts));
            new_graphs.insert(func, Arc::new(entry.graph));
            new_dependencies.insert(func, dependencies);
            kept_files.insert(file_id, current_hash);
            surviving += 1;
        }

        let mut inner = self.inner.write();
        inner.facts = new_facts;
        inner.graphs = new_graphs;
        inner.dependencies = new_dependencies;
        inner.file_hashes = kept_files;
        inner.prewarmed = false;
        inner.sanitizer_fingerprint = EMPTY_SANITIZER_FINGERPRINT;
        inner.sanitizer_tokens = Arc::new(TokenSet::default());
        inner.matcher_policy_fingerprint = MATCHER_POLICY_FINGERPRINT;
        surviving
    }

    /// Clear every entry. Forces the next `facts_for` / `prewarm_all`
    /// to recompute from scratch. Used by `--no-cache` callers +
    /// tests.
    pub fn clear(&self) {
        let mut inner = self.inner.write();
        inner.facts.clear();
        inner.graphs.clear();
        inner.dependencies.clear();
        inner.file_hashes.clear();
        inner.prewarmed = false;
        inner.sanitizer_fingerprint = 0;
        inner.matcher_policy_fingerprint = 0;
        drop(inner);
        *self.disk.write() = None;
    }

    /// Persist the cache to `path` as a `bincode`-encoded
    /// [`SerializableSnapshot`]. Atomic-and-durable:
    ///
    /// 1. Acquire an exclusive lockfile next to `path` so two
    ///    concurrent `bonsai-ninja index` invocations cannot race
    ///    on the rename. Stale lockfiles (orphaned by a crashed
    ///    process) are reclaimed when their pid is no longer alive.
    /// 2. Write to a uniquely-named tmp file in the same directory.
    /// 3. `sync_all()` the tmp file so its bytes hit storage.
    /// 4. `rename()` the tmp file over `path` (atomic on every
    ///    POSIX filesystem and ReFS/NTFS via MoveFileEx).
    /// 5. `sync_all()` the parent directory so the rename itself
    ///    is durable across power loss.
    ///
    /// Per `docs/contributing/design-patterns.mdx::Lossless Caches` — a partially
    /// written sidecar must not survive a crash and contradict the
    /// content-addressed contract.
    pub fn save_to_disk(&self, path: &Path, db: &AnalyzerDb) -> std::io::Result<()> {
        let mut snap = self.snapshot(db);
        snap.dependency_metadata_fingerprint = dependency_metadata_fingerprint_for_sidecar(path);
        let bytes =
            bincode::serialize(&snap).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        let _lock = SidecarWriteLock::acquire(path)?;
        let tmp = unique_sidecar_tmp_path(path);
        {
            let mut tmp_file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&tmp)?;
            use std::io::Write;
            tmp_file.write_all(&bytes)?;
            tmp_file.sync_all()?;
        }
        if let Err(err) = std::fs::rename(&tmp, path) {
            let _ = std::fs::remove_file(&tmp);
            return Err(err);
        }
        // Sync the parent directory so the rename's metadata reaches
        // disk. On Windows the open-directory dance isn't supported
        // by std; the journaled filesystem there makes the rename
        // durable on its own.
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                if let Ok(dir) = std::fs::File::open(parent) {
                    let _ = dir.sync_all();
                }
            }
        }
        Ok(())
    }

    /// Load from a sidecar written by [`Self::save_to_disk`].
    /// Returns the number of entries that survived version / content
    /// validation. Non-existent sidecar returns `Ok(0)` — nothing to
    /// load, not an error.
    pub fn load_from_disk(&self, path: &Path, db: &AnalyzerDb) -> std::io::Result<usize> {
        if !path.exists() {
            return Ok(0);
        }
        let bytes = std::fs::read(path)?;
        if snapshot_version_prefix(&bytes).is_some_and(|version| version != DATAFLOW_CACHE_VERSION) {
            return Ok(0);
        }
        let snap: SerializableSnapshot = match bincode::deserialize(&bytes) {
            Ok(s) => s,
            // Corrupt sidecar — treat as "nothing to load."
            Err(error) => {
                tracing::warn!(
                    path = %path.display(),
                    error = %error,
                    "ignoring corrupt dataflow sidecar"
                );
                return Ok(0);
            }
        };
        if snap.dependency_metadata_fingerprint != dependency_metadata_fingerprint_for_sidecar(path) {
            return Ok(0);
        }
        Ok(self.load_snapshot(snap, db))
    }

    /// Conventional location for the legacy bincode dataflow sidecar.
    /// Kept for backward-compatible warm-cache reloads written by
    /// older bonsai-ninja builds. New code should prefer
    /// [`Self::factstore_sidecar_path`] which is the streaming-prewarm
    /// target and bounds peak RAM.
    #[must_use]
    pub fn sidecar_path(workspace_root: &Path) -> PathBuf {
        workspace_bonsai_dir(workspace_root).join("dataflow.v2.bin")
    }

    /// Conventional location for the new disk-backed fact-store
    /// dataflow sidecar. Co-resides with the legacy sidecar; readers
    /// validate version + pipeline hash on open so a stale file is
    /// silently dropped.
    #[must_use]
    pub fn factstore_sidecar_path(workspace_root: &Path) -> PathBuf {
        workspace_bonsai_dir(workspace_root).join("dataflow.v3.factstore")
    }

    /// Open the factstore sidecar at `path` and swap it in as the
    /// cache's disk store. Returns the number of entries the file
    /// contains. Non-existent / version-mismatched / corrupt files
    /// silently return `Ok(0)` after logging.
    pub fn load_factstore_sidecar(&self, path: &Path, db: &AnalyzerDb) -> std::io::Result<usize> {
        if !path.exists() {
            return Ok(0);
        }
        let reader = match bonsai_factstore::FactStoreReader::open(
            path,
            DATAFLOW_FACTSTORE_TABLE_ID,
            dataflow_pipeline_hash(db, path),
        ) {
            Ok(reader) => reader,
            Err(err) => {
                tracing::warn!(
                    path = %path.display(),
                    error = %err,
                    "ignoring stale or corrupt dataflow factstore sidecar"
                );
                discard_stale_factstore_sidecar(path, &err);
                return Ok(0);
            }
        };
        let entries = reader.len();
        *self.disk.write() = Some(Arc::new(reader));
        Ok(entries)
    }

    /// Compatibility accessor. Sanitizers are reporting evidence and
    /// do not define a cache profile, so this is always empty.
    #[must_use]
    pub fn active_sanitizers(&self) -> Arc<TokenSet> {
        Arc::new(TokenSet::default())
    }
}

fn snapshot_version_prefix(bytes: &[u8]) -> Option<u32> {
    let prefix = bytes.get(..std::mem::size_of::<u32>())?;
    let mut raw = [0u8; std::mem::size_of::<u32>()];
    raw.copy_from_slice(prefix);
    Some(u32::from_le_bytes(raw))
}

/// Inter-process lock for `dataflow.v2.bin` writes. Implemented as an
/// atomic `O_CREAT | O_EXCL` lockfile next to the sidecar — two
/// concurrent `bonsai-ninja index` runs cannot both acquire it.
///
/// Stale lockfiles (left behind when a previous writer crashed) are
/// detected by reading the pid stored in the file and checking
/// whether that process is still alive; if not, the lockfile is
/// removed and acquisition is retried once.
struct SidecarWriteLock {
    path: PathBuf,
}

impl SidecarWriteLock {
    fn lock_path(sidecar: &Path) -> PathBuf {
        let mut path = sidecar.to_path_buf();
        let mut name: OsString = path
            .file_name()
            .map(OsString::from)
            .unwrap_or_else(|| OsString::from("dataflow"));
        name.push(".lock");
        path.set_file_name(name);
        path
    }

    fn acquire(sidecar: &Path) -> std::io::Result<Self> {
        let lock_path = Self::lock_path(sidecar);
        match Self::try_create(&lock_path) {
            Ok(lock) => Ok(lock),
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
                if Self::reclaim_if_stale(&lock_path) {
                    Self::try_create(&lock_path)
                } else {
                    Err(std::io::Error::new(
                        std::io::ErrorKind::WouldBlock,
                        format!(
                            "another bonsai-ninja process is writing the dataflow sidecar (lock: {})",
                            lock_path.display()
                        ),
                    ))
                }
            }
            Err(err) => Err(err),
        }
    }

    fn try_create(lock_path: &Path) -> std::io::Result<Self> {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(lock_path)?;
        use std::io::Write;
        let _ = writeln!(file, "{}", process::id());
        let _ = file.sync_all();
        Ok(Self {
            path: lock_path.to_path_buf(),
        })
    }

    fn reclaim_if_stale(lock_path: &Path) -> bool {
        let Ok(text) = std::fs::read_to_string(lock_path) else {
            return false;
        };
        let Ok(pid) = text.trim().parse::<u32>() else {
            // Unreadable pid → conservative: treat as live.
            return false;
        };
        if process_is_alive(pid) {
            return false;
        }
        std::fs::remove_file(lock_path).is_ok()
    }
}

impl Drop for SidecarWriteLock {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

#[cfg(unix)]
fn process_is_alive(pid: u32) -> bool {
    if pid == 0 {
        return true;
    }
    let path = format!("/proc/{pid}");
    if std::path::Path::new(&path).exists() {
        return true;
    }
    if cfg!(target_os = "linux") {
        return false;
    }
    // macOS / BSD do not expose Linux-style /proc. Use the POSIX
    // `kill -0` probe through the system utility so this crate can keep
    // `unsafe_code = "forbid"` and avoid a libc call. This path only
    // runs when a lockfile already exists, so the process-spawn cost is
    // outside the normal sidecar write path.
    match Command::new("kill")
        .arg("-0")
        .arg(pid.to_string())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
    {
        Ok(status) => status.success(),
        Err(_) => true,
    }
}

#[cfg(not(unix))]
fn process_is_alive(_pid: u32) -> bool {
    // Conservative on Windows: don't reclaim stale locks. Crashed
    // processes leave a manual-cleanup case; safer than racing a
    // running writer.
    true
}

fn content_hash(bytes: &[u8]) -> u64 {
    bonsai_hash::fnv1a_bytes64(bytes)
}

/// Compatibility fingerprint for the canonical graph profile. Older
/// sidecars carried a sanitizer profile here; current propagation is
/// sanitizer-neutral, so every persisted graph uses this sentinel.
const EMPTY_SANITIZER_FINGERPRINT: u128 = 0xE3E3_E3E3_E3E3_E3E3_E3E3_E3E3_E3E3_E3E3_u128;
const _: () = assert!(EMPTY_SANITIZER_FINGERPRINT != 0);

fn current_file_hashes(db: &AnalyzerDb) -> AHashMap<FileId, u64> {
    db.vfs()
        .all_files()
        .into_iter()
        .filter_map(|file| {
            let snap = db.vfs().snapshot(file).ok()?;
            Some((file, content_hash(snap.text.as_bytes())))
        })
        .collect()
}

/// Funnel `bonsai_factstore::FactStoreError` into `std::io::Error`
/// so the dataflow API stays uniform with the legacy bincode path.
fn map_factstore_io(err: bonsai_factstore::FactStoreError) -> std::io::Error {
    match err {
        bonsai_factstore::FactStoreError::Io(e) => e,
        other => std::io::Error::other(other),
    }
}

fn snapshot_call_graph(db: &AnalyzerDb) -> bonsai_callgraph::ResolvedCallGraph {
    let global = db.global_index();
    bonsai_callgraph::ResolvedCallGraph::build_with_file_info_and_super_tokens(
        global.as_ref(),
        |file| bonsai_resolve::alias_map_for_file(&db.imports_for(file)),
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
                .unwrap_or(bonsai_common::SUPER_RECEIVER_TOKENS)
        },
    )
}

impl DataFlowCache {
    /// Compute the file dependency set for `func` using the cache's
    /// internally-cached call graph (built once per cache lifetime).
    fn dependency_files_via_cache(&self, func: FuncId, db: &AnalyzerDb) -> AHashSet<FileId> {
        let global = db.global_index();
        let call_graph = self.call_graph_for(db);
        dependency_files(func, &call_graph, &global)
    }
}

fn dependency_files(
    func: FuncId,
    graph: &bonsai_callgraph::ResolvedCallGraph,
    global: &bonsai_index::GlobalIndex,
) -> AHashSet<FileId> {
    let mut out = AHashSet::new();
    let mut seen = AHashSet::new();
    let mut stack = vec![func];
    while let Some(next) = stack.pop() {
        if !seen.insert(next) {
            continue;
        }
        let sym = SymbolId::new(next.raw());
        if let Some(file) = global.declaring_file(sym) {
            out.insert(file);
        }
        for edge in graph.callees_of(next) {
            stack.push(edge.to);
        }
    }
    out
}

fn unique_sidecar_tmp_path(path: &Path) -> PathBuf {
    let counter = SIDECAR_TMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut name = path
        .file_name()
        .map(OsString::from)
        .unwrap_or_else(|| OsString::from("dataflow.v2.bin"));
    name.push(format!(".tmp.{}.{}", process::id(), counter));
    path.with_file_name(name)
}

#[cfg(test)]
#[path = "dataflow_tests.rs"]
mod tests;
