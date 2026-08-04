//! Workspace-wide source-seeded taint graph index.
//!
//! Stage 6 of the eager-graph roadmap: lift the per-invocation
//! `(source_func, sorted_seed_key) → EntryTaintGraph` memo map out of
//! `build_findings_chain_aware` so the answer persists across queries
//! within one CLI process. Each entry is the result of one
//! interprocedural taint pass for `(source_func, seeds)`; second and
//! later queries against the same `(workspace, rulepack)` reuse the
//! computation instead of replaying it.
//!
//! Invalidation: any file edit through `Workspace::ingest_dir` clears
//! the whole index — entries reference call edges that any source
//! change can invalidate. Rulepack-declared transfer semantics are part of
//! the entry key, and `clear_for_config` invalidates the index when that
//! semantic configuration changes.

use crate::cache_fingerprint::{
    dependency_metadata_fingerprint_for_sidecar, discard_stale_factstore_sidecar,
    workspace_content_fingerprint,
};
use crate::factstore_cleanup::{cleanup_valid_sidecar_temp_files, factstore_writer_suffix_is_valid};
use crate::taint_index_disk::{
    decode_verified, encode as encode_taint_graph_entry, factstore_key,
    TaintGraphEntry as DiskTaintGraphEntry,
};
use ahash::{AHashMap, AHashSet};
use bonsai_common::{workspace_bonsai_dir, FuncId, MATCHER_POLICY_FINGERPRINT};
use bonsai_db::AnalyzerDb;
use bonsai_factstore::{FactStoreReader, FactStoreWriter};
use bonsai_taint::EntryTaintGraph;
use fs2::FileExt;
use parking_lot::{Mutex, RwLock};
use std::collections::{BTreeSet, VecDeque};
use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// On-disk snapshot version for the workspace-wide taint graph.
/// Disk format is the streaming factstore; bumping this invalidates
/// every cached sidecar so consumers get a fresh build on next open.
// v17 (2026-08-03): target relevance now records whether the adapter-lowered
// field inverse is complete. Partial inverses are non-pruning, so older
// cached negative source graphs are not semantically reusable.
// v16 (2026-08-03): compiler-object v50, callgraph v28, and IDG semantic v71
// alter qualified storage/callable reachability; reject prior taint graphs.
// v15 (2026-07-31): lambda/local-function ownership, Perl package calls, and
// implicit-class constructor resolution changed; cached reachability must use
// the rebuilt linkage, callgraph, and IDG scope chain.
// v14 (2026-07-30): nested lexical endpoint identities changed with
// compiler-object v13; cached reachability must use the rebuilt IDG.
// v12 (2026-07-25): Security source graphs now execute against the exact
// source-to-sink corridor's backward target-demand relation. Older graphs
// were built with workspace-global sink demand and are not semantically
// interchangeable even though their wire shape is unchanged.
// v11 (2026-07-16): MessagePack replaces the retired binary codec.
// v10 (2026-07-01): taint graph/dataflow cache semantics changed to avoid
// seeding callee/module target components as value carriers and to keep exact
// RHS call spans for assignment-derived terminal calls.
// v9 (2026-05-27): taint graph derives from the IDG, whose construction
// and seeding changed enough that old graphs are no longer equivalent.
pub const TAINT_GRAPH_CACHE_VERSION: u32 = 17;

/// Caller-defined table id stamped into the factstore header. 4 is
/// the next slot after dataflow (2), value-flow (1), flow-ids (3).
const TAINT_GRAPH_TABLE_ID: u32 = 4;

/// Secondary safety bound on source-seeded graphs retained in memory.
///
/// Production retention is governed primarily by bytes because graph sizes
/// differ by orders of magnitude. The entry limit remains as a guard against
/// excessive metadata and for compatibility with existing SDK configuration.
pub const TAINT_GRAPH_RESIDENT_ENTRY_CAP: usize = 512;

fn configured_resident_entry_cap() -> usize {
    std::env::var("BONSAI_TAINT_GRAPH_CACHE_ENTRIES")
        .ok()
        .and_then(|raw| raw.parse::<usize>().ok())
        .unwrap_or(TAINT_GRAPH_RESIDENT_ENTRY_CAP)
}

fn configured_resident_budget_bytes() -> u64 {
    const BYTES_PER_MIB: u64 = 1024 * 1024;
    const DEFAULT_BUDGET_BYTES: u64 = 64 * BYTES_PER_MIB;
    const MIN_BUDGET_BYTES: u64 = 64 * 1024;
    const MAX_BUDGET_BYTES: u64 = 256 * BYTES_PER_MIB;
    std::env::var("BONSAI_TAINT_GRAPH_CACHE_MB")
        .ok()
        .and_then(|raw| raw.trim().parse::<u64>().ok())
        .and_then(|mib| mib.checked_mul(BYTES_PER_MIB))
        .or_else(|| {
            bonsai_common::effective_memory_limit_bytes()
                .map(|limit| (limit / 64).clamp(MIN_BUDGET_BYTES, MAX_BUDGET_BYTES))
        })
        .unwrap_or(DEFAULT_BUDGET_BYTES)
}

/// Pipeline-hash field in the factstore header. Folds the matcher
/// policy fingerprint, IDG semantic fingerprint, caller config fingerprint,
/// and workspace content fingerprint into 64 bits so matcher, graph,
/// rule/source, and source-file changes invalidate the cache file.
fn taint_graph_pipeline_hash(db: &AnalyzerDb, config_fingerprint: u64, sidecar_path: &Path) -> u64 {
    let raw = MATCHER_POLICY_FINGERPRINT;
    let policy_lo = raw as u64;
    let policy_hi = (raw >> 64) as u64;
    let content =
        workspace_content_fingerprint(db) ^ dependency_metadata_fingerprint_for_sidecar(sidecar_path);
    let semantic_version = u64::from(TAINT_GRAPH_CACHE_VERSION);
    // Mix in the caller's config fingerprint so a `--rules-dir` swap
    // produces a different pipeline hash and the new file invalidates
    // the old. `0` is the sentinel "no fingerprint set" value the
    // backward-compatible API used; treat it as opting out of the
    // config-bound check.
    if config_fingerprint == 0 {
        policy_lo ^ policy_hi ^ content ^ semantic_version ^ crate::idg_stitching_semantic_fingerprint()
    } else {
        policy_lo
            ^ policy_hi
            ^ content
            ^ config_fingerprint
            ^ semantic_version
            ^ crate::idg_stitching_semantic_fingerprint()
    }
}

/// Interned key for a sorted seed token set. Collisions are
/// deliberately impossible: identical seed sets hash to the same
/// `Vec<String>`.
pub type SeedShapeKey = Vec<String>;

/// One entry in the per-`(source_func, seed_shape)` taint-graph map.
pub type TaintGraphEntry = Arc<EntryTaintGraph>;

#[derive(Debug)]
struct ResidentGraphEntry {
    graph: TaintGraphEntry,
    estimated_bytes: u64,
}

/// Workspace-wide taint graph cache. Cleared on file edits.
#[derive(Debug)]
pub struct TaintGraphIndex {
    inner: RwLock<Inner>,
}

#[derive(Debug)]
struct Inner {
    /// `(source_func, sorted_seed_key)` → cached `EntryTaintGraph`.
    by_source_seed: AHashMap<(FuncId, SeedShapeKey), ResidentGraphEntry>,
    /// FIFO insertion order for bounded resident entries.
    resident_order: VecDeque<(FuncId, SeedShapeKey)>,
    /// Maximum number of decoded graphs resident in memory.
    resident_cap: usize,
    /// Maximum estimated bytes of decoded graph allocations retained in RAM.
    resident_budget_bytes: u64,
    /// Estimated bytes currently retained by `by_source_seed`.
    resident_bytes: u64,
    /// Optional fingerprint of the `InterTaintConfig` that produced
    /// the cached entries. Bump-on-mismatch lets the consumer tell
    /// whether a different rulepack would invalidate the cache.
    config_fingerprint: u64,
    /// Optional disk-backed source of truth, populated by
    /// [`TaintGraphIndex::load_from_disk`]. Lookups that miss the
    /// in-memory map probe this before reporting a true miss.
    disk: Option<Arc<FactStoreReader>>,
    /// Optional write-through factstore session. Security analyses
    /// enable this for exact command scopes so every graph computed
    /// during the scan is persisted immediately, even if the decoded
    /// graph is evicted from the resident cache before the command
    /// finishes.
    persist: Option<Arc<PersistSession>>,
}

#[derive(Debug)]
struct PersistSession {
    path: PathBuf,
    config_fingerprint: u64,
    /// Cross-process ownership of the target sidecar. The advisory lock is
    /// released by the OS on crash and therefore cannot strand a stale lock.
    lock_file: File,
    writer: Mutex<Option<FactStoreWriter>>,
    written_keys: Mutex<AHashSet<u64>>,
    existing: Option<Arc<FactStoreReader>>,
}

/// Result of starting one exact write-through cache session.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct PersistStartReport {
    /// Whether this call created a new writer.
    pub started: bool,
    /// Abandoned temp files removed while holding their target locks.
    pub temp_files_removed: usize,
    /// Finalized sidecars from older, incompatible schemas removed while
    /// holding their target locks.
    pub obsolete_sidecars_removed: usize,
}

fn persistence_lock_path(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(".lock");
    PathBuf::from(name)
}

fn acquire_persistence_lock(path: &Path) -> std::io::Result<File> {
    let lock_path = persistence_lock_path(path);
    if let Some(parent) = lock_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let lock_file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&lock_path)?;
    lock_file.try_lock_exclusive().map_err(|error| {
        if error.kind() == std::io::ErrorKind::WouldBlock {
            std::io::Error::new(
                std::io::ErrorKind::WouldBlock,
                format!(
                    "taint graph sidecar is owned by another process: {}",
                    path.display()
                ),
            )
        } else {
            error
        }
    })?;
    Ok(lock_file)
}

impl Inner {
    fn with_limits(resident_cap: usize, resident_budget_bytes: u64) -> Self {
        Self {
            by_source_seed: AHashMap::with_capacity(resident_cap.min(1024)),
            resident_order: VecDeque::with_capacity(resident_cap.min(1024)),
            resident_cap,
            resident_budget_bytes,
            resident_bytes: 0,
            config_fingerprint: 0,
            disk: None,
            persist: None,
        }
    }
}

impl Default for TaintGraphIndex {
    fn default() -> Self {
        Self {
            inner: RwLock::new(Inner::with_limits(
                configured_resident_entry_cap(),
                configured_resident_budget_bytes(),
            )),
        }
    }
}

impl TaintGraphIndex {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Build an index with a fixed resident-entry cap. Tests use
    /// this to exercise eviction; production callers normally use
    /// [`Self::new`].
    #[must_use]
    pub fn with_capacity(resident_cap: usize) -> Self {
        Self {
            inner: RwLock::new(Inner::with_limits(resident_cap, u64::MAX)),
        }
    }

    /// Build an index with byte-governed decoded-graph retention.
    ///
    /// Exact graphs larger than the budget are returned and may be persisted,
    /// but are not held resident. This is a cache limit, never an analysis
    /// limit.
    #[must_use]
    pub fn with_resident_budget_bytes(resident_budget_bytes: u64) -> Self {
        Self {
            inner: RwLock::new(Inner::with_limits(
                TAINT_GRAPH_RESIDENT_ENTRY_CAP,
                resident_budget_bytes,
            )),
        }
    }

    /// Look up a cached graph; `None` means "miss, you build it."
    #[must_use]
    pub fn get(&self, source_func: FuncId, seed_key: &[String]) -> Option<TaintGraphEntry> {
        // Drop the read guard's temporary before any potential write
        // upgrade on the disk-hydrate path.
        let cached = self
            .inner
            .read()
            .by_source_seed
            .get(&(source_func, seed_key.to_vec()))
            .map(|entry| Arc::clone(&entry.graph));
        if cached.is_some() {
            return cached;
        }
        self.try_hydrate_from_disk(source_func, seed_key)
    }

    /// Probe the disk store for the entry keyed at `(source_func,
    /// seed_key)`, decode the payload, verify the full key matches
    /// (guarding against the astronomical hash collision), and
    /// hydrate the in-memory map. Returns the cached graph on hit.
    fn try_hydrate_from_disk(&self, source_func: FuncId, seed_key: &[String]) -> Option<TaintGraphEntry> {
        let (reader, config_fingerprint) = {
            let inner = self.inner.read();
            (inner.disk.clone()?, inner.config_fingerprint)
        };
        let key = factstore_key(source_func, seed_key);
        let hit = reader.get(key).ok().flatten()?;
        let entry = decode_verified(&hit.payload, source_func, seed_key).ok()?;
        let arc = Arc::new(entry.graph);
        let map_key = (source_func, seed_key.to_vec());
        let mut inner = self.inner.write();
        // A file edit or rulepack/config swap can invalidate the index while
        // the payload is being read and decoded. Never repopulate the new
        // generation from that stale reader. Pointer identity also catches a
        // same-config sidecar reload after corruption/rebuild.
        if !disk_snapshot_is_current(&inner, &reader, config_fingerprint) {
            return None;
        }
        Some(insert_resident(&mut inner, map_key, arc).0)
    }

    /// Insert a freshly-computed graph. If an entry already exists
    /// for this key (because another worker beat us to it), keep the
    /// established one — both entries are derived from identical
    /// inputs, but the established one may already be referenced
    /// elsewhere.
    pub fn insert_if_absent(
        &self,
        source_func: FuncId,
        seed_key: SeedShapeKey,
        graph: TaintGraphEntry,
    ) -> TaintGraphEntry {
        let key = (source_func, seed_key);
        let (stored, should_persist) = {
            let mut inner = self.inner.write();
            insert_resident(&mut inner, key.clone(), graph)
        };
        if let Some(persist) = should_persist {
            if let Err(err) = persist_graph_entry(&persist, key.0, &key.1, &stored) {
                tracing::warn!(
                    path = %persist.path.display(),
                    error = %err,
                    "taint graph factstore write-through failed"
                );
            }
        }
        stored
    }

    /// Insert a freshly-computed graph and return the established
    /// entry. Cache persistence failures are returned to callers
    /// that want to surface them; most query paths should use
    /// [`Self::insert_if_absent`] so cache I/O remains best-effort.
    pub fn try_insert_if_absent(
        &self,
        source_func: FuncId,
        seed_key: SeedShapeKey,
        graph: TaintGraphEntry,
    ) -> std::io::Result<TaintGraphEntry> {
        let key = (source_func, seed_key);
        let (stored, should_persist) = {
            let mut inner = self.inner.write();
            insert_resident(&mut inner, key.clone(), graph)
        };
        if let Some(persist) = should_persist {
            persist_graph_entry(&persist, key.0, &key.1, &stored)?;
        }
        Ok(stored)
    }

    /// Drop every cached entry. Triggered by `Workspace::ingest_dir`
    /// when a file edit invalidates the underlying call graph.
    pub fn clear(&self) {
        let mut inner = self.inner.write();
        inner.by_source_seed.clear();
        inner.resident_order.clear();
        inner.resident_bytes = 0;
        inner.config_fingerprint = 0;
        inner.disk = None;
        inner.persist = None;
    }

    /// Drop entries when the caller's `InterTaintConfig` differs from
    /// the cached fingerprint. Returns `true` if entries were dropped.
    /// Security-analysis flow calls this with its rulepack's config
    /// fingerprint so a `--rules-dir` swap invalidates.
    pub fn clear_for_config(&self, config_fingerprint: u64) -> bool {
        let mut inner = self.inner.write();
        if inner.config_fingerprint == config_fingerprint {
            return false;
        }
        inner.by_source_seed.clear();
        inner.resident_order.clear();
        inner.resident_bytes = 0;
        inner.config_fingerprint = config_fingerprint;
        inner.disk = None;
        inner.persist = None;
        true
    }

    /// Number of cached graph entries — in-memory plus disk.
    #[must_use]
    pub fn len(&self) -> usize {
        let inner = self.inner.read();
        let in_memory = inner.by_source_seed.len();
        let on_disk = inner.disk.as_ref().map_or(0, |r| r.len());
        // Hydrated entries are in both maps; we don't have a cheap
        // way to compute the exact overlap (would require comparing
        // every key against the disk index), so the headline is the
        // max of the two as a conservative upper bound.
        in_memory.max(on_disk)
    }

    /// True iff the cache is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        let inner = self.inner.read();
        let mem_empty = inner.by_source_seed.is_empty();
        let disk_empty = inner.disk.as_ref().is_none_or(|r| r.is_empty());
        mem_empty && disk_empty
    }

    /// Number of decoded graph entries currently retained in RAM.
    #[must_use]
    pub fn resident_len(&self) -> usize {
        self.inner.read().by_source_seed.len()
    }

    /// Resident graph entry cap for this index.
    #[must_use]
    pub fn resident_capacity(&self) -> usize {
        self.inner.read().resident_cap
    }

    /// Estimated decoded graph bytes currently retained in RAM.
    #[must_use]
    pub fn resident_bytes(&self) -> u64 {
        self.inner.read().resident_bytes
    }

    /// Byte budget for decoded graph retention.
    #[must_use]
    pub fn resident_budget_bytes(&self) -> u64 {
        self.inner.read().resident_budget_bytes
    }

    /// Change the resident decoded-graph cap and evict immediately if
    /// the current cache is larger than the new bound. This is useful
    /// for one-shot broad CLI scans, where retaining decoded graphs
    /// across source groups costs more memory than it saves time.
    pub fn set_resident_capacity(&self, resident_cap: usize) {
        let mut inner = self.inner.write();
        inner.resident_cap = resident_cap;
        if resident_cap == 0 {
            inner.by_source_seed.clear();
            inner.resident_order.clear();
            inner.resident_bytes = 0;
            return;
        }
        while inner.by_source_seed.len() > resident_cap {
            if !evict_oldest_resident(&mut inner) {
                break;
            }
        }
    }

    /// Change the decoded-graph byte budget and evict immediately when the
    /// retained hot set is larger. Graph computation and factstore
    /// persistence remain exact; only reuse changes.
    pub fn set_resident_budget_bytes(&self, resident_budget_bytes: u64) {
        let mut inner = self.inner.write();
        inner.resident_budget_bytes = resident_budget_bytes;
        while inner.resident_bytes > resident_budget_bytes {
            if !evict_oldest_resident(&mut inner) {
                break;
            }
        }
    }

    /// Conventional sidecar path in the external workspace cache.
    #[must_use]
    pub fn sidecar_path(workspace_root: &Path) -> PathBuf {
        workspace_bonsai_dir(workspace_root)
            .join(format!("taint_graph.v{TAINT_GRAPH_CACHE_VERSION}.factstore"))
    }

    /// Conventional sidecar path for a specific taint/source analysis
    /// configuration. The fixed [`Self::sidecar_path`] remains the
    /// legacy no-config path; configured analyses get their own file
    /// so `source-analysis` and `taint-analysis` do not evict each
    /// other's warm facts.
    #[must_use]
    pub fn sidecar_path_for_config(workspace_root: &Path, config_fingerprint: u64) -> PathBuf {
        if config_fingerprint == 0 {
            return Self::sidecar_path(workspace_root);
        }
        workspace_bonsai_dir(workspace_root).join(format!(
            "taint_graph.v{TAINT_GRAPH_CACHE_VERSION}.{config_fingerprint:016x}.factstore"
        ))
    }

    /// Conventional sidecar path for a specific analysis phase and
    /// configuration. The phase label is part of the filename so
    /// source inventory and finding analysis keep independent warm
    /// files even if their transfer configuration otherwise matches.
    #[must_use]
    pub fn sidecar_path_for_config_namespace(
        workspace_root: &Path,
        namespace: &str,
        config_fingerprint: u64,
    ) -> PathBuf {
        let namespace = sanitize_sidecar_namespace(namespace);
        if namespace.is_empty() {
            return Self::sidecar_path_for_config(workspace_root, config_fingerprint);
        }
        workspace_bonsai_dir(workspace_root).join(format!(
            "taint_graph.v{TAINT_GRAPH_CACHE_VERSION}.{namespace}.{config_fingerprint:016x}.factstore"
        ))
    }

    /// Return the most recently modified taint-graph sidecar for
    /// diagnostics and cache stats. This preserves compatibility with
    /// the legacy fixed filename while allowing configured analyses to
    /// persist sidecars independently.
    #[must_use]
    pub fn latest_sidecar_path(workspace_root: &Path) -> PathBuf {
        let legacy = Self::sidecar_path(workspace_root);
        let Some(parent) = legacy.parent() else {
            return legacy;
        };
        let prefix = format!("taint_graph.v{TAINT_GRAPH_CACHE_VERSION}");
        let mut best: Option<(std::time::SystemTime, PathBuf)> = None;
        let Ok(entries) = std::fs::read_dir(parent) else {
            return legacy;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
                continue;
            };
            if !name.starts_with(&prefix) || !name.ends_with(".factstore") {
                continue;
            }
            let modified = entry
                .metadata()
                .and_then(|meta| meta.modified())
                .unwrap_or(std::time::SystemTime::UNIX_EPOCH);
            let replace = best.as_ref().is_none_or(|(best_modified, best_path)| {
                modified > *best_modified || (modified == *best_modified && path > *best_path)
            });
            if replace {
                best = Some((modified, path));
            }
        }
        best.map_or(legacy, |(_, path)| path)
    }

    /// Persist the index as a fact-store file. Streams the in-memory
    /// entries (and any entries already on disk that the in-memory
    /// map didn't cover) through the streaming writer so peak RAM
    /// stays bounded by the in-flight payload.
    pub fn save_to_disk(&self, path: &Path, db: &AnalyzerDb) -> std::io::Result<()> {
        let lock_file = acquire_persistence_lock(path)?;
        // Snapshot the in-memory state under a single read guard so
        // we don't hold it during file I/O.
        let inner = self.inner.read();
        let mem_entries: Vec<((FuncId, SeedShapeKey), TaintGraphEntry)> = inner
            .by_source_seed
            .iter()
            .map(|(key, entry)| (key.clone(), Arc::clone(&entry.graph)))
            .collect();
        let config_fingerprint = inner.config_fingerprint;
        let disk_reader = inner.disk.clone();
        drop(inner);

        let writer = FactStoreWriter::create_with_capacity(
            path,
            TAINT_GRAPH_TABLE_ID,
            taint_graph_pipeline_hash(db, config_fingerprint, path),
            mem_entries.len(),
            // Per-entry payload includes a graph that can be tens of
            // KB; size the BufWriter generously.
            mem_entries.len().saturating_mul(2048),
            mem_entries.len().saturating_mul(8),
        )
        .map_err(map_factstore_io)?;

        let mut written_keys = ahash::AHashSet::<u64>::with_capacity(mem_entries.len());
        for ((func, seeds), graph) in &mem_entries {
            let entry = DiskTaintGraphEntry {
                func_raw: func.raw(),
                seeds: seeds.clone(),
                graph: (**graph).clone(),
            };
            let payload = encode_taint_graph_entry(&entry);
            let key = factstore_key(*func, seeds);
            writer.add_owned(key, 0, payload).map_err(map_factstore_io)?;
            written_keys.insert(key);
        }
        // Forward-port any entries from the existing disk store that
        // the in-memory map didn't already cover. Skips collisions on
        // the rare hash-clash case.
        if let Some(reader) = disk_reader {
            for item in reader.iter() {
                let (key, hit) = item.map_err(map_factstore_io)?;
                if written_keys.contains(&key) {
                    continue;
                }
                writer
                    .add(key, hit.body_hash, &hit.payload)
                    .map_err(map_factstore_io)?;
                written_keys.insert(key);
            }
        }
        writer.finish().map_err(map_factstore_io)?;
        FileExt::unlock(&lock_file)?;
        Ok(())
    }

    /// Start a write-through factstore session for the current
    /// config. Newly inserted graphs are appended to a temp sidecar
    /// immediately, while the resident cache remains bounded.
    ///
    /// Returns `false` when a session for the same path/config is
    /// already active. Call [`Self::finish_persist_to_disk`] when
    /// the exact command scope has finished computing.
    pub fn begin_persist_to_disk(
        &self,
        path: &Path,
        db: &AnalyzerDb,
        config_fingerprint: u64,
    ) -> std::io::Result<bool> {
        self.begin_persist_to_disk_report(path, db, config_fingerprint)
            .map(|report| report.started)
    }

    /// Start write-through persistence and report safe crash-artifact cleanup.
    ///
    /// FactStore temp names contain the writer pid, but a pid alone is not a
    /// portable liveness proof. Instead this acquires each taint-sidecar's
    /// advisory target lock before unlinking its abandoned temps. Active
    /// writers retain their lock and are never touched.
    pub fn begin_persist_to_disk_report(
        &self,
        path: &Path,
        db: &AnalyzerDb,
        config_fingerprint: u64,
    ) -> std::io::Result<PersistStartReport> {
        let mut inner = self.inner.write();
        if let Some(active) = inner.persist.as_ref() {
            if active.path == path && active.config_fingerprint == config_fingerprint {
                return Ok(PersistStartReport::default());
            }
            return Err(std::io::Error::new(
                std::io::ErrorKind::WouldBlock,
                "another taint graph persistence session is active",
            ));
        }
        if inner.config_fingerprint != config_fingerprint {
            inner.by_source_seed.clear();
            inner.resident_order.clear();
            inner.resident_bytes = 0;
            inner.disk = None;
            inner.config_fingerprint = config_fingerprint;
        }
        let existing = inner.disk.clone();
        let lock_file = acquire_persistence_lock(path)?;
        // Ownership is established before cleanup: another process's active
        // target remains locked and its unique temp is never unlinked.
        let temp_files_removed = cleanup_abandoned_taint_graph_temp_files(path)?;
        let obsolete_sidecars_removed = prune_obsolete_taint_graph_sidecars(path)?;
        let writer = FactStoreWriter::create(
            path,
            TAINT_GRAPH_TABLE_ID,
            taint_graph_pipeline_hash(db, config_fingerprint, path),
        )
        .map_err(map_factstore_io)?;
        inner.persist = Some(Arc::new(PersistSession {
            path: path.to_path_buf(),
            config_fingerprint,
            lock_file,
            writer: Mutex::new(Some(writer)),
            written_keys: Mutex::new(AHashSet::default()),
            existing,
        }));
        Ok(PersistStartReport {
            started: true,
            temp_files_removed,
            obsolete_sidecars_removed,
        })
    }

    /// Finish the active write-through session. Existing disk entries
    /// not recomputed during this command are forward-ported into the
    /// new sidecar, preserving warm-cache coverage while still
    /// writing newly computed entries as a stream.
    pub fn finish_persist_to_disk(&self, db: &AnalyzerDb) -> std::io::Result<usize> {
        let persist = {
            let mut inner = self.inner.write();
            inner.persist.take()
        };
        let Some(persist) = persist else {
            return Ok(0);
        };

        if let Some(existing) = &persist.existing {
            for item in existing.iter() {
                let (key, hit) = item.map_err(map_factstore_io)?;
                if persist.written_keys.lock().contains(&key) {
                    continue;
                }
                let writer_guard = persist.writer.lock();
                let Some(writer) = writer_guard.as_ref() else {
                    return Err(std::io::Error::other(
                        "taint graph factstore writer already finished",
                    ));
                };
                writer
                    .add(key, hit.body_hash, &hit.payload)
                    .map_err(map_factstore_io)?;
                persist.written_keys.lock().insert(key);
            }
        }

        let writer = persist
            .writer
            .lock()
            .take()
            .ok_or_else(|| std::io::Error::other("taint graph factstore writer already finished"))?;
        let written = writer.finish().map_err(map_factstore_io)?;
        let _ = self.load_from_disk_for_config(&persist.path, db, persist.config_fingerprint)?;
        FileExt::unlock(&persist.lock_file)?;
        Ok(written)
    }

    /// Open a sidecar written with the legacy/no-config profile. New
    /// security callers should prefer [`Self::load_from_disk_for_config`]
    /// so a rulepack or taint-config change cannot hydrate stale
    /// graphs.
    pub fn load_from_disk(&self, path: &Path, db: &AnalyzerDb) -> std::io::Result<usize> {
        self.load_from_disk_for_config(path, db, 0)
    }

    /// Open the factstore sidecar at `path` and swap it in as the
    /// cache's disk store. Subsequent `get` calls hydrate one entry
    /// at a time on demand. Non-existent / corrupt/stale files
    /// silently return `Ok(0)` after logging.
    ///
    /// `config_fingerprint` is mixed into the pipeline-hash check so
    /// a `--rules-dir` swap (which produces a different fingerprint)
    /// causes the file open to fail and the cache to be rebuilt.
    pub fn load_from_disk_for_config(
        &self,
        path: &Path,
        db: &AnalyzerDb,
        config_fingerprint: u64,
    ) -> std::io::Result<usize> {
        let mut inner = self.inner.write();
        if inner.persist.is_some() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::WouldBlock,
                "cannot replace taint graph disk state during an active persistence session",
            ));
        }
        if !path.exists() {
            return Ok(0);
        }
        let reader = match FactStoreReader::open(
            path,
            TAINT_GRAPH_TABLE_ID,
            taint_graph_pipeline_hash(db, config_fingerprint, path),
        ) {
            Ok(reader) => reader,
            Err(err) => {
                tracing::warn!(
                    path = %path.display(),
                    error = %err,
                    "ignoring stale or corrupt taint-graph factstore sidecar"
                );
                discard_stale_factstore_sidecar(path, &err);
                return Ok(0);
            }
        };
        let entries = reader.len();
        inner.by_source_seed.clear();
        inner.resident_order.clear();
        inner.resident_bytes = 0;
        inner.config_fingerprint = config_fingerprint;
        inner.disk = Some(Arc::new(reader));
        inner.persist = None;
        Ok(entries)
    }

    /// Validate that a taint-graph factstore is structurally readable and
    /// carries the expected table id. Rulepack/config freshness is checked
    /// separately by cache manifests and command-specific fingerprints.
    pub fn validate_sidecar_file(path: &Path) -> std::io::Result<usize> {
        let reader = FactStoreReader::open_relaxed(path).map_err(map_factstore_io)?;
        if reader.header().table_id != TAINT_GRAPH_TABLE_ID {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "taint-graph factstore table id mismatch: file={} expected={}",
                    reader.header().table_id,
                    TAINT_GRAPH_TABLE_ID
                ),
            ));
        }
        Ok(reader.len())
    }
}

/// Explicit maintenance cleanup for temp files left by a process that was
/// terminated before [`FactStoreWriter`] could run `Drop`.
///
/// Callers must first establish exclusive ownership of the workspace cache
/// directory. Normal analysis never calls this function: blindly sweeping by
/// filename can unlink another process's active unique temp file.
pub fn cleanup_sidecar_temp_files(path: &Path) -> std::io::Result<usize> {
    cleanup_valid_sidecar_temp_files(path)
}

pub(crate) fn maintain_sidecar_cache(workspace_root: &Path) -> std::io::Result<()> {
    let current = TaintGraphIndex::sidecar_path(workspace_root);
    let lock_file = acquire_persistence_lock(&current)?;
    let cleanup_result = cleanup_abandoned_taint_graph_temp_files(&current)
        .and_then(|_| prune_obsolete_taint_graph_sidecars(&current))
        .map(|_| ());
    let unlock_result = FileExt::unlock(&lock_file);
    cleanup_result.and(unlock_result)
}

fn cleanup_abandoned_taint_graph_temp_files(owned_path: &Path) -> std::io::Result<usize> {
    let Some(parent) = owned_path.parent() else {
        return Ok(0);
    };
    let current_version = owned_path
        .file_name()
        .and_then(|name| name.to_str())
        .and_then(taint_graph_sidecar_version)
        .unwrap_or(TAINT_GRAPH_CACHE_VERSION);
    let mut targets = BTreeSet::new();
    let entries = match std::fs::read_dir(parent) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(error) => return Err(error),
    };
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        let Some((target_name, writer_suffix)) = name.rsplit_once(".tmp.") else {
            continue;
        };
        if factstore_writer_suffix_is_valid(writer_suffix)
            && taint_graph_sidecar_version(target_name).is_some_and(|version| version <= current_version)
        {
            targets.insert(parent.join(target_name));
        }
    }

    let mut removed = cleanup_valid_sidecar_temp_files(owned_path)?;
    for target in targets {
        if target == owned_path {
            continue;
        }
        let lock_file = match acquire_persistence_lock(&target) {
            Ok(lock_file) => lock_file,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(error) => {
                tracing::warn!(
                    path = %target.display(),
                    error = %error,
                    "skipping abandoned taint temp cleanup"
                );
                continue;
            }
        };
        match cleanup_valid_sidecar_temp_files(&target) {
            Ok(count) => removed = removed.saturating_add(count),
            Err(error) => {
                tracing::warn!(
                    path = %target.display(),
                    error = %error,
                    "abandoned taint temp cleanup failed"
                );
            }
        }
        if let Err(error) = FileExt::unlock(&lock_file) {
            tracing::warn!(
                path = %target.display(),
                error = %error,
                "abandoned taint temp cleanup lock release failed"
            );
        }
    }
    Ok(removed)
}

fn prune_obsolete_taint_graph_sidecars(current_path: &Path) -> std::io::Result<usize> {
    let Some(parent) = current_path.parent() else {
        return Ok(0);
    };
    let Some(current_version) = current_path
        .file_name()
        .and_then(|name| name.to_str())
        .and_then(taint_graph_sidecar_version)
    else {
        return Ok(0);
    };
    let entries = match std::fs::read_dir(parent) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(error) => return Err(error),
    };
    let mut obsolete = BTreeSet::new();
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };
        let file_type = match entry.file_type() {
            Ok(file_type) => file_type,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };
        if !file_type.is_file() {
            continue;
        }
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if taint_graph_sidecar_version(name).is_some_and(|version| version < current_version) {
            obsolete.insert(entry.path());
        }
    }

    let mut removed = 0usize;
    for target in obsolete {
        let lock_file = match acquire_persistence_lock(&target) {
            Ok(lock_file) => lock_file,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(error) => {
                tracing::warn!(
                    path = %target.display(),
                    error = %error,
                    "skipping superseded taint-graph sidecar cleanup"
                );
                continue;
            }
        };
        match std::fs::remove_file(&target) {
            Ok(()) => removed = removed.saturating_add(1),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                tracing::warn!(
                    path = %target.display(),
                    error = %error,
                    "superseded taint-graph sidecar cleanup failed"
                );
            }
        }
        if let Err(error) = FileExt::unlock(&lock_file) {
            tracing::warn!(
                path = %target.display(),
                error = %error,
                "superseded taint-graph sidecar cleanup lock release failed"
            );
        }
    }
    Ok(removed)
}

fn taint_graph_sidecar_version(name: &str) -> Option<u32> {
    let stem = name.strip_suffix(".factstore")?;
    let suffix = stem.strip_prefix("taint_graph.v")?;
    let version = suffix.split('.').next()?;
    (!version.is_empty() && version.bytes().all(|byte| byte.is_ascii_digit()))
        .then(|| version.parse().ok())
        .flatten()
}

fn disk_snapshot_is_current(inner: &Inner, reader: &Arc<FactStoreReader>, config_fingerprint: u64) -> bool {
    inner.config_fingerprint == config_fingerprint
        && inner
            .disk
            .as_ref()
            .is_some_and(|current| Arc::ptr_eq(current, reader))
}

fn insert_resident(
    inner: &mut Inner,
    key: (FuncId, SeedShapeKey),
    graph: TaintGraphEntry,
) -> (TaintGraphEntry, Option<Arc<PersistSession>>) {
    if let Some(existing) = inner.by_source_seed.get(&key) {
        return (Arc::clone(&existing.graph), None);
    }
    let persist = inner.persist.clone();
    let estimated_bytes = graph.estimated_resident_bytes();
    if inner.resident_cap == 0
        || inner.resident_budget_bytes == 0
        || estimated_bytes > inner.resident_budget_bytes
    {
        return (graph, persist);
    }
    while inner.by_source_seed.len() >= inner.resident_cap
        || inner.resident_bytes.saturating_add(estimated_bytes) > inner.resident_budget_bytes
    {
        if !evict_oldest_resident(inner) {
            break;
        }
    }
    inner.resident_order.push_back(key.clone());
    inner.resident_bytes = inner.resident_bytes.saturating_add(estimated_bytes);
    inner.by_source_seed.insert(
        key,
        ResidentGraphEntry {
            graph: Arc::clone(&graph),
            estimated_bytes,
        },
    );
    (graph, persist)
}

fn evict_oldest_resident(inner: &mut Inner) -> bool {
    let Some(oldest) = inner.resident_order.pop_front() else {
        return false;
    };
    if let Some(evicted) = inner.by_source_seed.remove(&oldest) {
        inner.resident_bytes = inner.resident_bytes.saturating_sub(evicted.estimated_bytes);
    }
    true
}

fn sanitize_sidecar_namespace(namespace: &str) -> String {
    namespace
        .chars()
        .map(|ch| match ch {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '_' => ch,
            _ => '_',
        })
        .collect()
}

fn persist_graph_entry(
    persist: &PersistSession,
    func: FuncId,
    seeds: &[String],
    graph: &EntryTaintGraph,
) -> std::io::Result<()> {
    let key = factstore_key(func, seeds);
    {
        let mut written = persist.written_keys.lock();
        if !written.insert(key) {
            return Ok(());
        }
    }
    let entry = DiskTaintGraphEntry {
        func_raw: func.raw(),
        seeds: seeds.to_vec(),
        graph: graph.clone(),
    };
    let payload = encode_taint_graph_entry(&entry);
    let writer_guard = persist.writer.lock();
    let Some(writer) = writer_guard.as_ref() else {
        return Err(std::io::Error::other(
            "taint graph factstore writer already finished",
        ));
    };
    writer.add_owned(key, 0, payload).map_err(map_factstore_io)?;
    Ok(())
}

/// Funnel `bonsai_factstore::FactStoreError` into `std::io::Error`.
fn map_factstore_io(err: bonsai_factstore::FactStoreError) -> std::io::Error {
    match err {
        bonsai_factstore::FactStoreError::Io(e) => e,
        other => std::io::Error::other(other),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stale_disk_snapshot_is_rejected_after_config_or_reader_change() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("taint.factstore");
        FactStoreWriter::create(&path, TAINT_GRAPH_TABLE_ID, 7)
            .expect("create factstore")
            .finish()
            .expect("finish factstore");
        let first = Arc::new(FactStoreReader::open(&path, TAINT_GRAPH_TABLE_ID, 7).expect("first reader"));
        let replacement =
            Arc::new(FactStoreReader::open(&path, TAINT_GRAPH_TABLE_ID, 7).expect("replacement reader"));

        let mut inner = Inner::with_limits(1, 1);
        inner.config_fingerprint = 42;
        inner.disk = Some(Arc::clone(&first));
        assert!(disk_snapshot_is_current(&inner, &first, 42));
        assert!(!disk_snapshot_is_current(&inner, &replacement, 42));

        inner.disk = Some(replacement);
        assert!(!disk_snapshot_is_current(&inner, &first, 42));
        assert!(!disk_snapshot_is_current(&inner, &first, 7));
    }
}
