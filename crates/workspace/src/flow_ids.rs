//! Workspace-wide per-function symbol-summary-id cache.
//!
//! For each function, hashes its exact compiler identity into a stable
//! content-addressed `F:` symbol-evidence id. Browse rows look up labels here
//! instead of expanding graph paths per command. Lives in
//! `bonsai_workspace` (not `bonsai_browse`) so prewarm + invalidation
//! sit on the same lifecycle as [`crate::dataflow::DataFlowCache`].
//!
//! The id uses the same compiler declaration hash as structural inspect.
//! One callable produces one id; graph fan-out cannot change its cost.

use crate::cache_fingerprint::{
    dependency_metadata_fingerprint_for_sidecar, discard_stale_factstore_sidecar,
    workspace_content_fingerprint, workspace_content_fingerprint_from_paths,
};
use crate::factstore_cleanup::{forward_port_unwritten_entries, map_factstore_io};
use crate::flow_ids_disk::{decode as decode_flow_id_entry, encode as encode_flow_id_entry, FlowIdEntry};
use ahash::{AHashMap, AHashSet};
use bonsai_common::{workspace_bonsai_dir, FuncId, MATCHER_POLICY_FINGERPRINT};
use bonsai_db::{AnalyzerDb, COMPILER_OBJECT_CACHE_VERSION};
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
// v14 (2026-08-17): persist the single symbol id as a scalar rather than a
// legacy vector of path-derived labels.
// v13 (2026-08-16): browse labels identify one compiler symbol summary;
// recursive upstream/downstream path materialization was removed.
// v12 (2026-08-07): bind flow-id freshness to the compiler frontend ABI so
// adapter call/identity changes cannot reuse paths derived from older IR.
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
pub const FLOW_IDS_CACHE_VERSION: u32 = 14;

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
        ^ crate::compiler_frontend_cache_fingerprint(COMPILER_OBJECT_CACHE_VERSION)
        ^ content_fingerprint
        ^ dependency_metadata_fingerprint_for_sidecar(sidecar_path)
}

#[derive(Default, Debug)]
pub struct FlowIdCache {
    inner: RwLock<Inner>,
}

#[derive(Default, Debug)]
struct Inner {
    ids: AHashMap<FuncId, Arc<str>>,
    prewarmed: bool,
    /// Optional disk-backed source of truth, populated by
    /// [`FlowIdCache::prewarm_to_disk`] or
    /// [`FlowIdCache::load_from_disk`]. Lookups that miss the
    /// in-memory map probe this before hashing the compiler header.
    disk: Option<Arc<FactStoreReader>>,
}

impl FlowIdCache {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Stable symbol-evidence id for `func`. O(1) on cache hit; a miss hashes
    /// only the exact compiler declaration header. This deliberately does
    /// not open a call graph or enumerate paths.
    pub fn id_for_func(&self, func: FuncId, db: &AnalyzerDb, vfs: &bonsai_vfs::Vfs) -> Arc<str> {
        // Drop the read guard's temporary before the write upgrade.
        let cached = self.inner.read().ids.get(&func).cloned();
        if let Some(hit) = cached {
            return hit;
        }
        if let Some(arc) = self.try_hydrate_from_disk(func) {
            return arc;
        }
        let headers = db.build_global_header_index();
        let id = symbol_evidence_id(headers.as_ref(), db, vfs, func);
        let arc: Arc<str> = Arc::from(id);
        let mut inner = self.inner.write();
        inner.ids.insert(func, arc.clone());
        arc
    }

    #[cfg(test)]
    fn cached_id(&self, func: FuncId) -> Option<Arc<str>> {
        self.inner.read().ids.get(&func).cloned()
    }

    /// Probe the disk store for `func`, decode the payload, and
    /// hydrate the in-memory cache. Returns the cached id on
    /// hit. `None` when there is no disk store, no entry for `func`,
    /// or the entry fails to decode.
    fn try_hydrate_from_disk(&self, func: FuncId) -> Option<Arc<str>> {
        let reader = self.inner.read().disk.clone()?;
        let hit = reader.get(u64::from(func.raw())).ok().flatten()?;
        let entry = decode_flow_id_entry(&hit.payload).ok()?;
        let arc: Arc<str> = Arc::from(entry.id);
        let mut inner = self.inner.write();
        let id = inner.ids.entry(func).or_insert_with(|| arc.clone()).clone();
        Some(id)
    }

    /// How many function entries the next `prewarm_all` call would
    /// compute — used to size the CLI progress bar before any work
    /// happens.
    pub fn pending_count(&self, db: &AnalyzerDb) -> usize {
        let global = db.build_global_header_index();
        let already: AHashSet<FuncId> = self.inner.read().ids.keys().copied().collect();
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

    /// Eagerly populate every function's summary id in parallel.
    /// `on_each_done` fires once per newly-populated entry (from a
    /// rayon worker, so it must be `Sync`); [`Self::pending_count`]
    /// returns the total up front.
    ///
    /// Skipped by the default CLI path in favour of the lazy
    /// on-demand populate inside [`Self::id_for_func`] — a
    /// single `browse` invocation typically only needs a handful
    /// of enclosing functions, so paying the build for *every*
    /// function in the workspace would be wasted work. Call this
    /// directly from daemon / LSP startup where the upfront
    /// investment amortises across many queries.
    pub fn prewarm_all_with_progress<F>(&self, db: &AnalyzerDb, vfs: &bonsai_vfs::Vfs, on_each_done: F)
    where
        F: Fn(FuncId) + Sync + Send,
    {
        let global = db.build_global_header_index();
        let already: AHashSet<FuncId> = self.inner.read().ids.keys().copied().collect();
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
        let results: Vec<(FuncId, Arc<str>)> = todo
            .par_iter()
            .map(|&f| {
                let id = symbol_evidence_id(global.as_ref(), db, vfs, f);
                on_each_done(f);
                (f, Arc::from(id))
            })
            .collect();
        let mut inner = self.inner.write();
        for (f, id) in results {
            inner.ids.insert(f, id);
        }
        inner.prewarmed = true;
    }

    /// No-progress shortcut for tests and callers that don't need
    /// a bar.
    pub fn prewarm_all(&self, db: &AnalyzerDb, vfs: &bonsai_vfs::Vfs) {
        self.prewarm_all_with_progress(db, vfs, |_| {});
    }

    /// Stream-and-write prewarm. Computes one summary id for every
    /// callable function in parallel, encodes each entry into a
    /// fact-store writer immediately so peak RAM is bounded by the
    /// in-flight rayon chunk, atomically replaces the sidecar at
    /// `path`, and opens the resulting file as the cache's disk
    /// store. After this call the in-memory map is empty;
    /// subsequent `id_for_func` calls hydrate one entry at a
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
                inner.ids.keys().copied().collect(),
                inner
                    .ids
                    .iter()
                    .map(|(&func, id)| (func, FlowIdEntry { id: id.to_string() }))
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
            // Each function owns exactly one short symbol-evidence id.
            todo.len().saturating_mul(256),
            todo.len(),
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
            let entry = FlowIdEntry {
                id: symbol_evidence_id(global.as_ref(), db, vfs, f),
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
        inner.ids.clear();
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
        inner.ids.clear();
        inner.prewarmed = false;
        inner.disk = None;
    }

    /// Release resident presentation ids after a whole-workspace batch has
    /// serialized them. This is allocation lifetime control only: an attached
    /// factstore remains the exact source for later hydration, and otherwise
    /// ids are deterministically recomputed from compiler headers.
    pub fn release_resident_ids(&self) {
        let mut inner = self.inner.write();
        inner.ids.clear();
        if inner.disk.is_none() {
            inner.prewarmed = false;
        }
    }
}

fn symbol_evidence_id(
    headers: &GlobalIndex,
    db: &AnalyzerDb,
    vfs: &bonsai_vfs::Vfs,
    symbol: FuncId,
) -> String {
    compute_structural_flow_id(headers, db, vfs, &[symbol])
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

#[cfg(test)]
#[path = "flow_ids_tests.rs"]
mod tests;
