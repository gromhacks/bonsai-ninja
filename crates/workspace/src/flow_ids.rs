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
//! Default cached per-function DFS is capped at `MAX_CHAINS` /
//! `MAX_PROBES`; truncated functions render with a `…` suffix.
//! Exact consumers can request uncached exhaustive labels with
//! [`FlowIdLabelOptions::exhaustive`].

use crate::cache_fingerprint::{
    dependency_metadata_fingerprint_for_sidecar, discard_stale_factstore_sidecar,
    workspace_content_fingerprint, workspace_content_fingerprint_from_paths,
};
use crate::factstore_cleanup::{forward_port_unwritten_entries, map_factstore_io};
use crate::flow_ids_disk::{decode as decode_flow_id_entry, encode as encode_flow_id_entry, FlowIdEntry};
use ahash::{AHashMap, AHashSet};
use bonsai_callgraph::ResolvedCallGraph;
use bonsai_common::{workspace_bonsai_dir, FuncId, MATCHER_POLICY_FINGERPRINT};
use bonsai_db::AnalyzerDb;
use bonsai_factstore::{FactStoreReader, FactStoreWriter};
use bonsai_index::GlobalIndex;
use bonsai_lang_api::DeclKind;
use parking_lot::{Mutex, RwLock};
use rayon::prelude::*;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Caller-defined table id stamped into the flow-id factstore. 3 is
/// the next free slot after dataflow (2) and value-flow (1).
const FLOW_IDS_TABLE_ID: u32 = 3;

/// On-disk format version. Bump when the encoding changes so old
/// sidecars are rejected on open.
// v11 (2026-08-03): regenerate structural flow ids after compiler-object v50
// canonicalized file-derived identities and callable-reference facts.
// v10 (2026-07-31): structural flow ids hash exact compiler declaration
// identities instead of display-name sequences, eliminating overload/module
// collisions and duplicate navigation ids.
// v9 (2026-07-30): nested lexical endpoint identities changed with
// compiler-object v13, so enumerated flow paths must be rebuilt.
// v7 (2026-07-16): MessagePack replaces the retired binary codec.
// v6 (2026-05-27): downstream of IDG/adapter semantic changes,
// enumerated chains can differ, so reject older sidecars.
pub const FLOW_IDS_CACHE_VERSION: u32 = 11;

/// Pipeline-hash field in the factstore header. Folds the matcher
/// policy fingerprint into 64 bits and mixes in the current workspace
/// content fingerprint so source changes cannot reuse stale FuncId-
/// keyed labels.
fn flow_ids_pipeline_hash(db: &AnalyzerDb, sidecar_path: &Path) -> u64 {
    flow_ids_pipeline_hash_for_content(workspace_content_fingerprint(db), sidecar_path)
}

fn flow_ids_pipeline_hash_for_content(content_fingerprint: u64, sidecar_path: &Path) -> u64 {
    let raw = MATCHER_POLICY_FINGERPRINT;
    (raw as u64)
        ^ ((raw >> 64) as u64)
        ^ u64::from(FLOW_IDS_CACHE_VERSION)
        ^ content_fingerprint
        ^ dependency_metadata_fingerprint_for_sidecar(sidecar_path)
}

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

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct FlowIdLabelOptions {
    pub max_chains: usize,
    pub max_probes: usize,
    pub downstream_depth: usize,
    pub downstream_breadth: usize,
    pub max_labels_per_func: usize,
}

impl FlowIdLabelOptions {
    #[must_use]
    pub const fn exhaustive() -> Self {
        Self {
            max_chains: usize::MAX,
            max_probes: usize::MAX,
            downstream_depth: usize::MAX,
            downstream_breadth: usize::MAX,
            max_labels_per_func: usize::MAX,
        }
    }
}

impl Default for FlowIdLabelOptions {
    fn default() -> Self {
        Self {
            max_chains: MAX_CHAINS,
            max_probes: MAX_PROBES,
            downstream_depth: DOWNSTREAM_DEPTH,
            downstream_breadth: DOWNSTREAM_BREADTH,
            max_labels_per_func: MAX_LABELS_PER_FUNC,
        }
    }
}

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
    /// Optional disk-backed source of truth, populated by
    /// [`FlowIdCache::prewarm_to_disk`] or
    /// [`FlowIdCache::load_from_disk`]. Lookups that miss the
    /// in-memory map probe this before falling back to the engine.
    disk: Option<Arc<FactStoreReader>>,
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
        // Drop the read guard's temporary before the write upgrade.
        let cached = self.inner.read().labels.get(&func).cloned();
        if let Some(hit) = cached {
            return hit;
        }
        if let Some(arc) = self.try_hydrate_from_disk(func) {
            return arc;
        }
        let cg = self.call_graph(db, vfs);
        let options = FlowIdLabelOptions::default();
        let (chains, trunc) = enumerate_chains(&cg, func, options.max_chains, options.max_probes);
        let headers = db.build_global_header_index();
        // Mirror `inspect`'s chain extension: each backward chain
        // (root → … → target) gets every resolvable downstream call
        // path DFS-enumerated from its tail. The hashed name sequence
        // — and therefore the flow id — matches what
        // `inspect --query <enclosing_fn>` would emit, so ids from
        // browse paste directly into `inspect --flow F:...`.
        let (ids, label_trunc) = collect_flow_ids_for_chains(&cg, headers.as_ref(), db, vfs, chains, options);
        let arc: Arc<[String]> = Arc::from(ids.into_boxed_slice());
        let mut inner = self.inner.write();
        inner.labels.insert(func, arc.clone());
        if trunc || label_trunc {
            inner.truncated.insert(func);
        }
        arc
    }

    /// Flow-id labels for a batch of functions. This is the same
    /// computation as [`Self::labels_for_func`], but it computes cold
    /// misses in parallel against one shared resolved call graph and
    /// bulk-inserts the results into the cache.
    ///
    /// Full-workspace consumers such as native export need labels for
    /// every callable; driving that through `labels_for_func` serially
    /// repeats avoidable scheduler and lock overhead on large graphs.
    /// The output remains a per-function cache lookup contract: cached
    /// and disk-backed entries are reused, missing entries are computed
    /// exactly with the same caps and truncation bit as the scalar path.
    pub fn labels_for_funcs(
        &self,
        funcs: &[FuncId],
        db: &AnalyzerDb,
        vfs: &bonsai_vfs::Vfs,
    ) -> Vec<(FuncId, Arc<[String]>, bool)> {
        let options = FlowIdLabelOptions::default();
        if funcs.is_empty() {
            return Vec::new();
        }

        let mut unique: Vec<FuncId> = Vec::with_capacity(funcs.len());
        let mut seen: AHashSet<FuncId> = AHashSet::new();
        for &func in funcs {
            if seen.insert(func) {
                unique.push(func);
            }
        }

        let mut resolved: AHashMap<FuncId, (Arc<[String]>, bool)> = AHashMap::new();
        let mut missing: Vec<FuncId> = Vec::new();
        for func in unique {
            if let Some(line) = self.cached_line(func) {
                resolved.insert(func, line);
            } else if let Some(line) = self.try_hydrate_from_disk_line(func) {
                resolved.insert(func, line);
            } else {
                missing.push(func);
            }
        }

        if !missing.is_empty() {
            let cg = self.call_graph(db, vfs);
            let headers = db.build_global_header_index();
            let computed: Vec<(FuncId, Arc<[String]>, bool)> = missing
                .par_iter()
                .map(|&f| {
                    let (chains, trunc) = enumerate_chains(&cg, f, options.max_chains, options.max_probes);
                    let (ids, label_trunc) =
                        collect_flow_ids_for_chains(&cg, headers.as_ref(), db, vfs, chains, options);
                    (f, Arc::from(ids.into_boxed_slice()), trunc || label_trunc)
                })
                .collect();
            {
                let mut inner = self.inner.write();
                for (func, labels, truncated) in &computed {
                    inner.labels.insert(*func, labels.clone());
                    if *truncated {
                        inner.truncated.insert(*func);
                    }
                }
            }
            for (func, labels, truncated) in computed {
                resolved.insert(func, (labels, truncated));
            }
        }

        funcs
            .iter()
            .filter_map(|func| {
                resolved
                    .get(func)
                    .map(|(labels, truncated)| (*func, labels.clone(), *truncated))
            })
            .collect()
    }

    /// Flow-id labels for a batch of functions with caller-selected
    /// bounds. The default option path delegates to the cached/disk
    /// backed implementation above; non-default options are computed
    /// fresh so an exhaustive export cannot accidentally reuse a
    /// bounded sidecar line.
    pub fn labels_for_funcs_with_options(
        &self,
        funcs: &[FuncId],
        db: &AnalyzerDb,
        vfs: &bonsai_vfs::Vfs,
        options: FlowIdLabelOptions,
    ) -> Vec<(FuncId, Arc<[String]>, bool)> {
        if options == FlowIdLabelOptions::default() {
            return self.labels_for_funcs(funcs, db, vfs);
        }
        if funcs.is_empty() {
            return Vec::new();
        }

        let mut unique: Vec<FuncId> = Vec::with_capacity(funcs.len());
        let mut seen: AHashSet<FuncId> = AHashSet::new();
        for &func in funcs {
            if seen.insert(func) {
                unique.push(func);
            }
        }

        let cg = self.call_graph(db, vfs);
        let headers = db.build_global_header_index();
        let computed_rows: Vec<(FuncId, Arc<[String]>, bool)> = unique
            .par_iter()
            .map(|&f| {
                let (chains, trunc) = enumerate_chains(&cg, f, options.max_chains, options.max_probes);
                let (ids, label_trunc) =
                    collect_flow_ids_for_chains(&cg, headers.as_ref(), db, vfs, chains, options);
                (f, Arc::from(ids.into_boxed_slice()), trunc || label_trunc)
            })
            .collect();
        let computed: AHashMap<FuncId, (Arc<[String]>, bool)> = computed_rows
            .into_iter()
            .map(|(func, labels, truncated)| (func, (labels, truncated)))
            .collect();

        funcs
            .iter()
            .filter_map(|func| {
                computed
                    .get(func)
                    .map(|(labels, truncated)| (*func, labels.clone(), *truncated))
            })
            .collect()
    }

    /// Flow-id labels from caller-provided backward chain sets.
    ///
    /// Export already enumerates per-target chain sets for its chain
    /// evidence sections. Feeding those exact chains here avoids a
    /// second whole-workspace chain enumeration pass while preserving
    /// the same downstream extension, hashing, caps, and truncation
    /// semantics as [`Self::labels_for_funcs_with_options`].
    pub fn labels_for_chain_sets_with_options(
        &self,
        chain_sets: Vec<(FuncId, Vec<Vec<FuncId>>, bool)>,
        db: &AnalyzerDb,
        vfs: &bonsai_vfs::Vfs,
        options: FlowIdLabelOptions,
    ) -> Vec<(FuncId, Arc<[String]>, bool)> {
        let headers = db.build_global_header_index();
        self.labels_for_chain_sets_with_index_and_options(chain_sets, db, vfs, headers.as_ref(), options)
    }

    /// Flow-id labels from caller-provided backward chains and the compiler
    /// header table already owned by the surrounding semantic phase.
    ///
    /// Whole-workspace exporters must use this form: rebuilding a body-level
    /// global index after releasing the frontend phase reparses every source
    /// file and overlaps those AST arenas with the complete callgraph.
    pub fn labels_for_chain_sets_with_index_and_options(
        &self,
        chain_sets: Vec<(FuncId, Vec<Vec<FuncId>>, bool)>,
        db: &AnalyzerDb,
        vfs: &bonsai_vfs::Vfs,
        headers: &GlobalIndex,
        options: FlowIdLabelOptions,
    ) -> Vec<(FuncId, Arc<[String]>, bool)> {
        if chain_sets.is_empty() {
            return Vec::new();
        }
        let cg = self.call_graph(db, vfs);
        let computed: Vec<(FuncId, Arc<[String]>, bool)> = chain_sets
            .into_par_iter()
            .map(|(func, chains, chain_truncated)| {
                let (ids, label_trunc) = collect_flow_ids_for_chains(&cg, headers, db, vfs, chains, options);
                (
                    func,
                    Arc::from(ids.into_boxed_slice()),
                    chain_truncated || label_trunc,
                )
            })
            .collect();
        if options == FlowIdLabelOptions::default() {
            let mut inner = self.inner.write();
            for (func, labels, truncated) in &computed {
                inner.labels.insert(*func, labels.clone());
                if *truncated {
                    inner.truncated.insert(*func);
                }
            }
        }
        computed
    }

    fn cached_line(&self, func: FuncId) -> Option<(Arc<[String]>, bool)> {
        let inner = self.inner.read();
        let labels = inner.labels.get(&func)?.clone();
        Some((labels, inner.truncated.contains(&func)))
    }

    /// Probe the disk store for `func`, decode the payload, and
    /// hydrate the in-memory cache. Returns the cached labels on
    /// hit. `None` when there is no disk store, no entry for `func`,
    /// or the entry fails to decode.
    fn try_hydrate_from_disk(&self, func: FuncId) -> Option<Arc<[String]>> {
        self.try_hydrate_from_disk_line(func).map(|(labels, _)| labels)
    }

    fn try_hydrate_from_disk_line(&self, func: FuncId) -> Option<(Arc<[String]>, bool)> {
        let reader = self.inner.read().disk.clone()?;
        let hit = reader.get(u64::from(func.raw())).ok().flatten()?;
        let entry = decode_flow_id_entry(&hit.payload).ok()?;
        let entry_truncated = entry.truncated;
        let arc: Arc<[String]> = Arc::from(entry.labels.into_boxed_slice());
        let mut inner = self.inner.write();
        let labels = inner.labels.entry(func).or_insert_with(|| arc.clone()).clone();
        if entry_truncated {
            inner.truncated.insert(func);
        }
        let truncated = inner.truncated.contains(&func);
        Some((labels, truncated))
    }

    /// Build (or return) the shared resolved call graph. Single
    /// builder lock keeps two concurrent queries from both paying
    /// the build cost.
    fn call_graph(&self, db: &AnalyzerDb, _vfs: &bonsai_vfs::Vfs) -> Arc<ResolvedCallGraph> {
        // Drop the read guard's temporary before the write upgrade.
        let cached = self.inner.read().cg.clone();
        if let Some(cg) = cached {
            return cg;
        }
        let built = crate::build_resolved_call_graph_snapshot(db);
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
    ///
    /// Forces a hydrate when the entry is on disk but not yet in
    /// memory, so the disk record's `truncated` bit is honoured.
    #[must_use]
    pub fn was_truncated(&self, func: FuncId) -> bool {
        if self.inner.read().labels.contains_key(&func) {
            return self.inner.read().truncated.contains(&func);
        }
        let _ = self.try_hydrate_from_disk(func);
        self.inner.read().truncated.contains(&func)
    }

    /// How many function entries the next `prewarm_all` call would
    /// compute — used to size the CLI progress bar before any work
    /// happens.
    pub fn pending_count(&self, db: &AnalyzerDb) -> usize {
        let global = db.build_global_header_index();
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
        let global = db.build_global_header_index();
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
                let options = FlowIdLabelOptions::default();
                let (chains, trunc) = enumerate_chains(&cg, f, options.max_chains, options.max_probes);
                let (ids, label_trunc) =
                    collect_flow_ids_for_chains(&cg, global.as_ref(), db, vfs, chains, options);
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

    /// Stream-and-write prewarm. Computes flow-id labels for every
    /// callable function in parallel, encodes each entry into a
    /// fact-store writer immediately so peak RAM is bounded by the
    /// in-flight rayon chunk, atomically replaces the sidecar at
    /// `path`, and opens the resulting file as the cache's disk
    /// store. After this call the in-memory map is empty;
    /// subsequent `labels_for_func` calls hydrate one entry at a
    /// time on demand.
    pub fn prewarm_to_disk<F>(
        &self,
        path: &Path,
        db: &AnalyzerDb,
        vfs: &bonsai_vfs::Vfs,
        on_each_done: F,
    ) -> std::io::Result<usize>
    where
        F: Fn(FuncId) + Sync + Send,
    {
        let cg = self.call_graph(db, vfs);
        let global = db.build_global_header_index();
        let mut funcs: Vec<FuncId> = Vec::new();
        for file in global.all_files() {
            for decl in global.decls_in(file) {
                if matches!(
                    decl.kind,
                    DeclKind::Function | DeclKind::Method | DeclKind::Constructor
                ) {
                    funcs.push(FuncId::new(decl.symbol.raw()));
                }
            }
        }
        let (already, memory_entries): (AHashSet<FuncId>, Vec<(FuncId, FlowIdEntry)>) = {
            let inner = self.inner.read();
            (
                inner.labels.keys().copied().collect(),
                inner
                    .labels
                    .iter()
                    .map(|(&func, labels)| {
                        (
                            func,
                            FlowIdEntry {
                                labels: labels.iter().cloned().collect(),
                                truncated: inner.truncated.contains(&func),
                            },
                        )
                    })
                    .collect(),
            )
        };
        let disk_clone = self.inner.read().disk.clone();
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
            self.inner.write().prewarmed = true;
            if path.exists() {
                let _ = self.load_from_disk(path, db);
            }
            return Ok(0);
        }
        // Channel-based writer: workers push entries through the
        // queue; a dedicated writer thread serializes file I/O.
        let writer = FactStoreWriter::create_with_capacity(
            path,
            FLOW_IDS_TABLE_ID,
            flow_ids_pipeline_hash(db, path),
            todo.len(),
            // Flow-id labels are short (8-16 char hex hashes) and
            // capped at MAX_LABELS_PER_FUNC per function, so the
            // payload bytes scale modestly.
            todo.len().saturating_mul(256),
            todo.len().saturating_mul(MAX_LABELS_PER_FUNC),
        )
        .map_err(map_factstore_io)?;
        let written_keys = Mutex::new(AHashSet::<u64>::default());
        let write_error = Mutex::new(None::<std::io::Error>);
        for (func, entry) in memory_entries {
            let key = u64::from(func.raw());
            let payload = encode_flow_id_entry(&entry);
            writer.add_owned(key, 0, payload).map_err(map_factstore_io)?;
            written_keys.lock().insert(key);
        }
        todo.par_iter().for_each(|&f| {
            if write_error.lock().is_some() {
                return;
            }
            let options = FlowIdLabelOptions::default();
            let (chains, trunc) = enumerate_chains(&cg, f, options.max_chains, options.max_probes);
            let (ids, label_trunc) =
                collect_flow_ids_for_chains(&cg, global.as_ref(), db, vfs, chains, options);
            let entry = FlowIdEntry {
                labels: ids,
                truncated: trunc || label_trunc,
            };
            let payload = encode_flow_id_entry(&entry);
            let key = u64::from(f.raw());
            if let Err(err) = writer.add_owned(key, 0, payload) {
                let mut first_error = write_error.lock();
                if first_error.is_none() {
                    *first_error = Some(map_factstore_io(err));
                }
            } else {
                written_keys.lock().insert(key);
            }
            on_each_done(f);
        });
        if let Some(error) = write_error.lock().take() {
            return Err(error);
        }
        forward_port_unwritten_entries(disk_clone.as_deref(), &writer, &written_keys)?;
        let written = writer.finish().map_err(map_factstore_io)?;
        let reader = FactStoreReader::open(path, FLOW_IDS_TABLE_ID, flow_ids_pipeline_hash(db, path))
            .map_err(map_factstore_io)?;
        let mut inner = self.inner.write();
        inner.labels.clear();
        inner.truncated.clear();
        inner.disk = Some(Arc::new(reader));
        inner.prewarmed = true;
        Ok(written)
    }

    /// Conventional sidecar path in the external workspace cache.
    #[must_use]
    pub fn sidecar_path(workspace_root: &Path) -> PathBuf {
        workspace_bonsai_dir(workspace_root).join(format!("flow_ids.v{FLOW_IDS_CACHE_VERSION}.factstore"))
    }

    /// Open the factstore sidecar at `path` and swap it in as the
    /// cache's disk store. Returns the number of entries the file
    /// contains. Non-existent / version-mismatched / corrupt files
    /// silently return `Ok(0)` after logging.
    pub fn load_from_disk(&self, path: &Path, db: &AnalyzerDb) -> std::io::Result<usize> {
        if !path.exists() {
            return Ok(0);
        }
        let reader = match FactStoreReader::open(path, FLOW_IDS_TABLE_ID, flow_ids_pipeline_hash(db, path)) {
            Ok(reader) => reader,
            Err(err) => {
                tracing::warn!(
                    path = %path.display(),
                    error = %err,
                    "ignoring stale or corrupt flow-ids factstore sidecar"
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

    /// Validate that a flow-id factstore is structurally readable and
    /// carries the expected table id. This does not prove freshness for a
    /// workspace; callers combine it with manifest/source freshness checks.
    pub fn validate_sidecar_file(path: &Path) -> std::io::Result<usize> {
        let reader = FactStoreReader::open_relaxed(path).map_err(map_factstore_io)?;
        if reader.header().table_id != FLOW_IDS_TABLE_ID {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "flow-id factstore table id mismatch: file={} expected={}",
                    reader.header().table_id,
                    FLOW_IDS_TABLE_ID
                ),
            ));
        }
        Ok(reader.len())
    }

    /// Validate a flow-id factstore against the exact source path/hash set
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
            FLOW_IDS_TABLE_ID,
            flow_ids_pipeline_hash_for_content(content, path),
        )
        .map_err(map_factstore_io)?;
        Ok(reader.len())
    }

    /// Drop every entry. Called by the workspace-wide
    /// invalidation path when a file changes — coarse but correct.
    pub fn invalidate_all(&self) {
        let mut inner = self.inner.write();
        inner.cg = None;
        inner.labels.clear();
        inner.truncated.clear();
        inner.prewarmed = false;
        inner.disk = None;
    }

    /// Seed the workspace-shared resolved call graph as the cached
    /// graph for this flow-id cache so the lazy `call_graph()`
    /// build is skipped. Called once at workspace open after the
    /// workspace builds its own canonical graph; saves rebuilding
    /// the same content twice.
    pub fn seed_call_graph(&self, graph: Arc<ResolvedCallGraph>) {
        self.inner.write().cg = Some(graph);
    }

    /// Release only the shared graph allocation after a batch consumer has
    /// completed. Computed labels and truncation metadata remain valid.
    pub fn release_call_graph(&self) {
        self.inner.write().cg = None;
    }

    /// Release resident presentation labels after a whole-workspace batch has
    /// serialized them. This is allocation lifetime control only: an attached
    /// factstore remains the exact source for later hydration, and otherwise
    /// labels are deterministically recomputed from the canonical callgraph.
    pub fn release_resident_labels(&self) {
        let mut inner = self.inner.write();
        inner.labels.clear();
        inner.truncated.clear();
        if inner.disk.is_none() {
            inner.prewarmed = false;
        }
    }
}

fn collect_flow_ids_for_chains(
    cg: &ResolvedCallGraph,
    headers: &GlobalIndex,
    db: &AnalyzerDb,
    vfs: &bonsai_vfs::Vfs,
    chains: Vec<Vec<FuncId>>,
    options: FlowIdLabelOptions,
) -> (Vec<String>, bool) {
    let mut seen: AHashSet<String> = AHashSet::new();
    let mut truncated = false;
    let mut call_paths = CallPathEnumerator::new(cg);
    'chains: for chain in chains {
        let (extended_paths, path_truncated) =
            call_paths.enumerate_from(&chain, options.downstream_depth, options.downstream_breadth);
        if path_truncated {
            truncated = true;
        }
        for extended in extended_paths {
            if extended.is_empty() {
                continue;
            }
            seen.insert(compute_structural_flow_id(headers, db, vfs, &extended));
            if seen.len() >= options.max_labels_per_func {
                truncated = true;
                break 'chains;
            }
        }
    }
    let mut ids: Vec<String> = seen.into_iter().collect();
    ids.sort();
    (ids, truncated)
}

struct CallPathEnumerator<'a> {
    cg: &'a ResolvedCallGraph,
    resolvable_callees_cache: AHashMap<FuncId, Vec<FuncId>>,
}

impl<'a> CallPathEnumerator<'a> {
    fn new(cg: &'a ResolvedCallGraph) -> Self {
        Self {
            cg,
            resolvable_callees_cache: AHashMap::new(),
        }
    }

    fn enumerate_from(
        &mut self,
        base: &[FuncId],
        max_extra: usize,
        max_paths: usize,
    ) -> (Vec<Vec<FuncId>>, bool) {
        if base.is_empty() {
            return (Vec::new(), false);
        }
        let mut out: Vec<Vec<FuncId>> = Vec::new();
        let mut stack: Vec<(Vec<FuncId>, usize)> = vec![(base.to_vec(), 0)];
        let mut truncated = false;
        while let Some((path, extra)) = stack.pop() {
            if out.len() >= max_paths {
                truncated = true;
                break;
            }
            let Some(&tail) = path.last() else {
                continue;
            };
            if extra >= max_extra {
                out.push(path);
                continue;
            }
            let mut resolvable: Vec<FuncId> = self
                .resolvable_callees(tail)
                .iter()
                .copied()
                .filter(|callee| !path.contains(callee))
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
        (out, truncated)
    }

    fn resolvable_callees(&mut self, caller: FuncId) -> &[FuncId] {
        if !self.resolvable_callees_cache.contains_key(&caller) {
            let out = resolved_callees_from_graph(self.cg, caller);
            self.resolvable_callees_cache.insert(caller, out);
        }
        self.resolvable_callees_cache
            .get(&caller)
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }
}

fn resolved_callees_from_graph(cg: &ResolvedCallGraph, caller: FuncId) -> Vec<FuncId> {
    // ResolvedCallGraph edges are emitted from concrete FlowEvent::Call
    // sites and now carry that source span. Reusing the graph's
    // adjacency list keeps flow-id downstream expansion aligned with
    // inspect without re-running alias resolution for every edge.
    let mut out: Vec<FuncId> = cg
        .callees_of(caller)
        .filter(|edge| edge.precision.is_semantic())
        .map(|edge| edge.to)
        .collect();
    out.sort_by_key(|f| f.raw());
    out.dedup();
    out
}

/// Look up a function's display name in the compiler header table. Returns
/// empty when the function id isn't known (for example, an unresolved
/// external). Flow-id rendering never needs declaration bodies.
/// Stable structural `F:` id over exact compiler declaration identities.
///
/// Human display names are deliberately insufficient: overloads and same-name
/// functions in different modules routinely produce the same name sequence.
/// Each hop therefore contributes its adapter language, workspace-relative
/// file, declaration kind/module/qualified name, and Tree-sitter name span.
/// These are compiler headers, so callers never hydrate declaration bodies.
#[must_use]
pub fn compute_structural_flow_id(
    headers: &GlobalIndex,
    db: &AnalyzerDb,
    vfs: &bonsai_vfs::Vfs,
    chain: &[FuncId],
) -> String {
    let mut hasher = bonsai_hash::Hasher::new();
    let mut absorb = |value: &str| {
        hasher.absorb(value.as_bytes());
        hasher.absorb_separator();
    };
    absorb("bonsai.structural-flow.v2");
    let workspace_root = db.workspace_root();
    for &func in chain {
        absorb("hop");
        let Some(decl) = headers.decl_of(bonsai_common::SymbolId::new(func.raw())) else {
            absorb("unknown-compiler-symbol");
            absorb(&func.raw().to_string());
            continue;
        };
        let file = decl.span.file;
        let path = vfs.path(file).ok();
        let stable_path = path.as_deref().map_or_else(
            || format!("<file:{}>", file.raw()),
            |path| {
                workspace_root
                    .as_deref()
                    .and_then(|root| path.strip_prefix(root).ok())
                    .unwrap_or(path)
                    .to_string_lossy()
                    .replace('\\', "/")
            },
        );
        absorb("language");
        absorb(
            db.adapter_for(file)
                .map_or("<unknown-language>", |adapter| adapter.language_id().as_str()),
        );
        absorb("path");
        absorb(&stable_path);
        absorb("kind");
        absorb(&format!("{:?}", decl.kind));
        absorb("module-count");
        absorb(&decl.module_path.segments.len().to_string());
        for segment in &decl.module_path.segments {
            absorb("module-segment");
            absorb(segment);
        }
        absorb("qualified-name");
        absorb(decl.qualified_name.as_deref().unwrap_or(&decl.name));
        absorb("name-span-start");
        absorb(&decl.name_span.start.to_string());
        absorb("name-span-end");
        absorb(&decl.name_span.end.to_string());
    }
    format!("F:{:016x}", hasher.finish())
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

/// Backward DFS over `cg` from `target` to its roots. Returns the
/// chain paths (entry → target) as slices of [`FuncId`]; a
/// `truncated` flag is set when either the chain cap or the probe
/// budget was hit. Precision is discarded — the flow-id cache only
/// hashes names — but the underlying enumeration is the canonical
/// `bonsai_callgraph::chains::enumerate_chains_resolved`. Earlier
/// this carried a private byte-equivalent copy that drifted on
/// cycle / precision-cut edges; consolidating eliminates the
/// browse F: id / `inspect --flow F:…` parity hazard.
fn enumerate_chains(
    cg: &ResolvedCallGraph,
    target: FuncId,
    max_chains: usize,
    max_probes: usize,
) -> (Vec<Vec<FuncId>>, bool) {
    let (chains, truncation) =
        bonsai_callgraph::chains::enumerate_chains_resolved(cg, target, max_chains, max_probes);
    let truncated = truncation.is_truncated();
    (chains.into_iter().map(|c| c.funcs).collect(), truncated)
}

#[cfg(test)]
#[path = "flow_ids_tests.rs"]
mod tests;
