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
//! change can invalidate. The rulepack-coupling concern (different
//! rulepacks may demand different `source_bearing_functions`) is
//! handled by exposing a `clear_for_config` hook the security analysis
//! can call when its `InterTaintConfig` changes.

use crate::cache_fingerprint::{
    dependency_metadata_fingerprint_for_sidecar, discard_stale_factstore_sidecar,
    workspace_content_fingerprint,
};
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
use std::collections::VecDeque;
use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// On-disk snapshot version for the workspace-wide taint graph.
/// Disk format is the streaming factstore; bumping this invalidates
/// every cached sidecar so consumers get a fresh build on next open.
// v10 (2026-07-01): taint graph/dataflow cache semantics changed to avoid
// seeding callee/module target components as value carriers and to keep exact
// RHS call spans for assignment-derived terminal calls.
// v9 (2026-05-27): taint graph derives from the IDG, whose construction
// and seeding changed enough that old graphs are no longer equivalent.
pub const TAINT_GRAPH_CACHE_VERSION: u32 = 10;

/// Caller-defined table id stamped into the factstore header. 4 is
/// the next slot after dataflow (2), value-flow (1), flow-ids (3).
const TAINT_GRAPH_TABLE_ID: u32 = 4;

/// Default number of source-seeded graphs retained in memory.
///
/// This is a cache cap, not an analysis cap: evicted graphs are
/// recomputed or rehydrated from the factstore. The value is large
/// enough to cover normal SDK command reuse while preventing the
/// historical Redis-scale failure mode where every source graph
/// stayed resident for the whole scan.
pub const TAINT_GRAPH_RESIDENT_ENTRY_CAP: usize = 512;

fn configured_resident_entry_cap() -> usize {
    std::env::var("BONSAI_TAINT_GRAPH_CACHE_ENTRIES")
        .ok()
        .and_then(|raw| raw.parse::<usize>().ok())
        .unwrap_or(TAINT_GRAPH_RESIDENT_ENTRY_CAP)
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
    // legacy bincode path used; treat it as opting out of the
    // config-bound check.
    let build_fp = crate::build_fingerprint_hash();
    if config_fingerprint == 0 {
        policy_lo
            ^ policy_hi
            ^ content
            ^ semantic_version
            ^ crate::idg_stitching_semantic_fingerprint()
            ^ build_fp
    } else {
        policy_lo
            ^ policy_hi
            ^ content
            ^ config_fingerprint
            ^ semantic_version
            ^ crate::idg_stitching_semantic_fingerprint()
            ^ build_fp
    }
}

/// Interned key for a sorted seed token set. Collisions are
/// deliberately impossible: identical seed sets hash to the same
/// `Vec<String>`.
pub type SeedShapeKey = Vec<String>;

/// One entry in the per-`(source_func, seed_shape)` taint-graph map.
pub type TaintGraphEntry = Arc<EntryTaintGraph>;

/// Workspace-wide taint graph cache. Cleared on file edits.
#[derive(Debug)]
pub struct TaintGraphIndex {
    inner: RwLock<Inner>,
}

#[derive(Debug)]
struct Inner {
    /// `(source_func, sorted_seed_key)` → cached `EntryTaintGraph`.
    by_source_seed: AHashMap<(FuncId, SeedShapeKey), TaintGraphEntry>,
    /// FIFO insertion order for bounded resident entries.
    resident_order: VecDeque<(FuncId, SeedShapeKey)>,
    /// Maximum number of decoded graphs resident in memory.
    resident_cap: usize,
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
    fn with_capacity(resident_cap: usize) -> Self {
        Self {
            by_source_seed: AHashMap::with_capacity(resident_cap.min(1024)),
            resident_order: VecDeque::with_capacity(resident_cap.min(1024)),
            resident_cap,
            config_fingerprint: 0,
            disk: None,
            persist: None,
        }
    }
}

impl Default for TaintGraphIndex {
    fn default() -> Self {
        Self::with_capacity(configured_resident_entry_cap())
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
            inner: RwLock::new(Inner::with_capacity(resident_cap)),
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
            .cloned();
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
        let reader = self.inner.read().disk.clone()?;
        let key = factstore_key(source_func, seed_key);
        let hit = reader.get(key).ok().flatten()?;
        let entry = decode_verified(&hit.payload, source_func, seed_key).ok()?;
        let arc = Arc::new(entry.graph);
        let map_key = (source_func, seed_key.to_vec());
        let mut inner = self.inner.write();
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
            return;
        }
        while inner.by_source_seed.len() > resident_cap {
            let Some(oldest) = inner.resident_order.pop_front() else {
                break;
            };
            inner.by_source_seed.remove(&oldest);
        }
    }

    /// Conventional sidecar path under `<workspace>/.bonsai/`.
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
            .map(|(k, v)| (k.clone(), v.clone()))
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
        let mut inner = self.inner.write();
        if let Some(active) = inner.persist.as_ref() {
            if active.path == path && active.config_fingerprint == config_fingerprint {
                return Ok(false);
            }
            return Err(std::io::Error::new(
                std::io::ErrorKind::WouldBlock,
                "another taint graph persistence session is active",
            ));
        }
        if inner.config_fingerprint != config_fingerprint {
            inner.by_source_seed.clear();
            inner.resident_order.clear();
            inner.disk = None;
            inner.config_fingerprint = config_fingerprint;
        }
        let existing = inner.disk.clone();
        let lock_file = acquire_persistence_lock(path)?;
        // Check session ownership before creating a temp writer. Constructing
        // first let a losing concurrent caller unlink/replace the live temp.
        // Automatic temp sweeping is intentionally absent because another
        // process may own a unique active temp for the same target.
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
        Ok(true)
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
    let Some(parent) = path.parent() else {
        return Ok(0);
    };
    let Some(file_name) = path.file_name().and_then(|name| name.to_str()) else {
        return Ok(0);
    };
    let prefix = format!("{file_name}.tmp.");
    let mut removed = 0usize;
    let entries = match std::fs::read_dir(parent) {
        Ok(entries) => entries,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(err) => return Err(err),
    };
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => continue,
            Err(err) => return Err(err),
        };
        let name = entry.file_name();
        if !name.to_string_lossy().starts_with(&prefix) {
            continue;
        }
        match std::fs::remove_file(entry.path()) {
            Ok(()) => removed += 1,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => return Err(err),
        }
    }
    Ok(removed)
}

fn insert_resident(
    inner: &mut Inner,
    key: (FuncId, SeedShapeKey),
    graph: TaintGraphEntry,
) -> (TaintGraphEntry, Option<Arc<PersistSession>>) {
    if let Some(existing) = inner.by_source_seed.get(&key) {
        return (existing.clone(), None);
    }
    let persist = inner.persist.clone();
    if inner.resident_cap == 0 {
        return (graph, persist);
    }
    while inner.by_source_seed.len() >= inner.resident_cap {
        let Some(oldest) = inner.resident_order.pop_front() else {
            break;
        };
        inner.by_source_seed.remove(&oldest);
    }
    inner.resident_order.push_back(key.clone());
    inner.by_source_seed.insert(key, graph.clone());
    (graph, persist)
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
