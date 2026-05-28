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
    workspace_content_fingerprint,
};
use crate::flow_ids_disk::{decode as decode_flow_id_entry, encode as encode_flow_id_entry, FlowIdEntry};
use ahash::{AHashMap, AHashSet};
use bonsai_callgraph::ResolvedCallGraph;
use bonsai_common::{workspace_bonsai_dir, FuncId, SymbolId, MATCHER_POLICY_FINGERPRINT};
use bonsai_db::AnalyzerDb;
use bonsai_factstore::{FactStoreReader, FactStoreWriter};
use bonsai_lang_api::DeclKind;
use parking_lot::RwLock;
use rayon::prelude::*;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Caller-defined table id stamped into the flow-id factstore. 3 is
/// the next free slot after dataflow (2) and value-flow (1).
const FLOW_IDS_TABLE_ID: u32 = 3;

/// On-disk format version. Bump when the encoding changes so old
/// sidecars are rejected on open.
// v6 (2026-05-27): downstream of the IDG/adapter semantic changes this
// WIP introduced — enumerated chains can differ, so reject older sidecars.
pub const FLOW_IDS_CACHE_VERSION: u32 = 6;

/// Pipeline-hash field in the factstore header. Folds the matcher
/// policy fingerprint into 64 bits and mixes in the current workspace
/// content fingerprint so source changes cannot reuse stale FuncId-
/// keyed labels.
fn flow_ids_pipeline_hash(db: &AnalyzerDb, sidecar_path: &Path) -> u64 {
    let raw = MATCHER_POLICY_FINGERPRINT;
    (raw as u64)
        ^ ((raw >> 64) as u64)
        ^ u64::from(FLOW_IDS_CACHE_VERSION)
        ^ workspace_content_fingerprint(db)
        ^ dependency_metadata_fingerprint_for_sidecar(sidecar_path)
        ^ crate::build_fingerprint_hash()
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
        // Mirror `inspect`'s chain extension: each backward chain
        // (root → … → target) gets every resolvable downstream call
        // path DFS-enumerated from its tail. The hashed name sequence
        // — and therefore the flow id — matches what
        // `inspect --query <enclosing_fn>` would emit, so ids from
        // browse paste directly into `inspect --flow F:...`.
        let (ids, label_trunc) = collect_flow_ids_for_chains(&cg, db, chains, options);
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
            let path_resolver = SharedCallPathResolver::build(&cg, db);
            let computed: Vec<(FuncId, Arc<[String]>, bool)> = missing
                .par_iter()
                .map(|&f| {
                    let (chains, trunc) = enumerate_chains(&cg, f, options.max_chains, options.max_probes);
                    let (ids, label_trunc) = collect_flow_ids_for_chains_with_shared(
                        &cg,
                        db,
                        chains,
                        options,
                        Some(&path_resolver),
                    );
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
        let path_resolver = SharedCallPathResolver::build(&cg, db);
        let computed_rows: Vec<(FuncId, Arc<[String]>, bool)> = unique
            .par_iter()
            .map(|&f| {
                let (chains, trunc) = enumerate_chains(&cg, f, options.max_chains, options.max_probes);
                let (ids, label_trunc) =
                    collect_flow_ids_for_chains_with_shared(&cg, db, chains, options, Some(&path_resolver));
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
        if chain_sets.is_empty() {
            return Vec::new();
        }
        let cg = self.call_graph(db, vfs);
        let path_resolver = SharedCallPathResolver::build(&cg, db);
        let computed: Vec<(FuncId, Arc<[String]>, bool)> = chain_sets
            .into_par_iter()
            .map(|(func, chains, chain_truncated)| {
                let (ids, label_trunc) =
                    collect_flow_ids_for_chains_with_shared(&cg, db, chains, options, Some(&path_resolver));
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
        let global = db.global_index();
        let built = ResolvedCallGraph::build_with_file_info_and_super_tokens(
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
        let path_resolver = SharedCallPathResolver::build(&cg, db);
        let results: Vec<(FuncId, Arc<[String]>, bool)> = todo
            .par_iter()
            .map(|&f| {
                let options = FlowIdLabelOptions::default();
                let (chains, trunc) = enumerate_chains(&cg, f, options.max_chains, options.max_probes);
                let (ids, label_trunc) =
                    collect_flow_ids_for_chains_with_shared(&cg, db, chains, options, Some(&path_resolver));
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
        let global = db.global_index();
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
        let path_resolver = SharedCallPathResolver::build(&cg, db);
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
        let written_keys = std::sync::Mutex::new(AHashSet::<u64>::default());
        for (func, entry) in memory_entries {
            let key = u64::from(func.raw());
            let payload = encode_flow_id_entry(&entry);
            writer.add(key, 0, &payload).map_err(map_factstore_io)?;
            written_keys.lock().expect("written keys lock").insert(key);
        }
        todo.par_iter().for_each(|&f| {
            let options = FlowIdLabelOptions::default();
            let (chains, trunc) = enumerate_chains(&cg, f, options.max_chains, options.max_probes);
            let (ids, label_trunc) =
                collect_flow_ids_for_chains_with_shared(&cg, db, chains, options, Some(&path_resolver));
            let entry = FlowIdEntry {
                labels: ids,
                truncated: trunc || label_trunc,
            };
            let payload = encode_flow_id_entry(&entry);
            let key = u64::from(f.raw());
            if let Err(err) = writer.add(key, 0, &payload) {
                tracing::warn!(error = %err, "flow-ids factstore add failed");
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
        let reader = FactStoreReader::open(path, FLOW_IDS_TABLE_ID, flow_ids_pipeline_hash(db, path))
            .map_err(map_factstore_io)?;
        let mut inner = self.inner.write();
        inner.labels.clear();
        inner.truncated.clear();
        inner.disk = Some(Arc::new(reader));
        inner.prewarmed = true;
        Ok(written)
    }

    /// Conventional sidecar path under `workspace_root/.bonsai/`.
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
}

/// Funnel `bonsai_factstore::FactStoreError` into `std::io::Error`
/// so callers don't pivot on the inner error variant.
fn map_factstore_io(err: bonsai_factstore::FactStoreError) -> std::io::Error {
    match err {
        bonsai_factstore::FactStoreError::Io(e) => e,
        other => std::io::Error::other(other),
    }
}

fn collect_flow_ids_for_chains(
    cg: &ResolvedCallGraph,
    db: &AnalyzerDb,
    chains: Vec<Vec<FuncId>>,
    options: FlowIdLabelOptions,
) -> (Vec<String>, bool) {
    collect_flow_ids_for_chains_with_shared(cg, db, chains, options, None)
}

fn collect_flow_ids_for_chains_with_shared(
    cg: &ResolvedCallGraph,
    db: &AnalyzerDb,
    chains: Vec<Vec<FuncId>>,
    options: FlowIdLabelOptions,
    shared: Option<&SharedCallPathResolver>,
) -> (Vec<String>, bool) {
    let mut seen: AHashSet<String> = AHashSet::new();
    let mut truncated = false;
    let mut call_paths = CallPathEnumerator::new(cg, db, shared);
    let mut names: AHashMap<FuncId, String> = AHashMap::new();
    'chains: for chain in chains {
        let (extended_paths, path_truncated) =
            call_paths.enumerate_from(&chain, options.downstream_depth, options.downstream_breadth);
        if path_truncated {
            truncated = true;
        }
        for extended in extended_paths {
            let chain_names: Vec<String> = extended
                .iter()
                .map(|&fi| {
                    shared
                        .and_then(|resolver| resolver.name(fi).map(str::to_owned))
                        .unwrap_or_else(|| {
                            names
                                .entry(fi)
                                .or_insert_with(|| func_display_name(db, fi))
                                .clone()
                        })
                })
                .filter(|n| !n.is_empty())
                .collect();
            if chain_names.is_empty() {
                continue;
            }
            seen.insert(compute_flow_id(&chain_names));
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

struct SharedCallPathResolver {
    resolvable_callees: AHashMap<FuncId, Arc<[FuncId]>>,
    names: AHashMap<FuncId, String>,
}

impl SharedCallPathResolver {
    fn build(cg: &ResolvedCallGraph, db: &AnalyzerDb) -> Self {
        let global = db.global_index();
        let mut funcs: Vec<FuncId> = Vec::new();
        let mut names: AHashMap<FuncId, String> = AHashMap::new();
        for file in global.all_files() {
            for decl in global.decls_in(file) {
                if !matches!(
                    decl.kind,
                    DeclKind::Function | DeclKind::Method | DeclKind::Constructor
                ) {
                    continue;
                }
                let func = FuncId::new(decl.symbol.raw());
                funcs.push(func);
                names.insert(func, decl.name.clone());
            }
        }

        let rows: Vec<(FuncId, Arc<[FuncId]>)> = funcs
            .par_iter()
            .map(|&caller| {
                let callees = compute_resolvable_callees(cg, db, caller);
                (caller, Arc::from(callees.into_boxed_slice()))
            })
            .collect();
        let resolvable_callees = rows.into_iter().collect();
        Self {
            resolvable_callees,
            names,
        }
    }

    fn name(&self, func: FuncId) -> Option<&str> {
        self.names.get(&func).map(String::as_str)
    }

    fn resolvable_callees(&self, caller: FuncId) -> &[FuncId] {
        self.resolvable_callees
            .get(&caller)
            .map(|callees| callees.as_ref())
            .unwrap_or(&[])
    }
}

struct CallPathEnumerator<'a> {
    cg: &'a ResolvedCallGraph,
    db: &'a AnalyzerDb,
    shared: Option<&'a SharedCallPathResolver>,
    resolvable_callees_cache: AHashMap<FuncId, Vec<FuncId>>,
}

impl<'a> CallPathEnumerator<'a> {
    fn new(
        cg: &'a ResolvedCallGraph,
        db: &'a AnalyzerDb,
        shared: Option<&'a SharedCallPathResolver>,
    ) -> Self {
        Self {
            cg,
            db,
            shared,
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
        let global = self.db.global_index();
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
            let Some(_tail_decl) = global.decl_of(SymbolId::new(tail.raw())) else {
                out.push(path);
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
        if let Some(shared) = self.shared {
            return shared.resolvable_callees(caller);
        }
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

fn compute_resolvable_callees(cg: &ResolvedCallGraph, _db: &AnalyzerDb, caller: FuncId) -> Vec<FuncId> {
    resolved_callees_from_graph(cg, caller)
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
