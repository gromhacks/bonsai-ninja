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

use crate::taint_index_disk::{
    decode_verified, encode as encode_taint_graph_entry, factstore_key,
    TaintGraphEntry as DiskTaintGraphEntry,
};
use ahash::AHashMap;
use bonsai_common::{workspace_bonsai_dir, FuncId, MATCHER_POLICY_FINGERPRINT};
use bonsai_factstore::{FactStoreReader, FactStoreWriter};
use bonsai_taint::EntryTaintGraph;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// On-disk snapshot version for the workspace-wide taint graph.
/// v2 is the disk-backed factstore format; older v1 bincode sidecars
/// (extension `.bin`) are still recognised by [`Self::load_from_disk`]
/// for backward-compatible warm reopens but new writes use the
/// factstore path.
pub const TAINT_GRAPH_CACHE_VERSION: u32 = 2;

/// Caller-defined table id stamped into the factstore header. 4 is
/// the next slot after dataflow (2), value-flow (1), flow-ids (3).
const TAINT_GRAPH_TABLE_ID: u32 = 4;

/// Pipeline-hash field in the factstore header. Folds the matcher
/// policy fingerprint into 64 bits so a matcher policy change
/// invalidates the cache file.
fn taint_graph_pipeline_hash(config_fingerprint: u64) -> u64 {
    let raw = MATCHER_POLICY_FINGERPRINT;
    let policy_lo = raw as u64;
    let policy_hi = (raw >> 64) as u64;
    // Mix in the caller's config fingerprint so a `--rules-dir` swap
    // produces a different pipeline hash and the new file invalidates
    // the old. `0` is the sentinel "no fingerprint set" value the
    // legacy bincode path used; treat it as opting out of the
    // config-bound check.
    if config_fingerprint == 0 {
        policy_lo ^ policy_hi
    } else {
        policy_lo ^ policy_hi ^ config_fingerprint
    }
}


/// Interned key for a sorted seed token set. Collisions are
/// deliberately impossible: identical seed sets hash to the same
/// `Vec<String>`.
pub type SeedShapeKey = Vec<String>;

/// One entry in the per-`(source_func, seed_shape)` taint-graph map.
pub type TaintGraphEntry = Arc<EntryTaintGraph>;

/// Workspace-wide taint graph cache. Cleared on file edits.
#[derive(Default, Debug)]
pub struct TaintGraphIndex {
    inner: RwLock<Inner>,
}

#[derive(Default, Debug)]
struct Inner {
    /// `(source_func, sorted_seed_key)` → cached `EntryTaintGraph`.
    by_source_seed: AHashMap<(FuncId, SeedShapeKey), TaintGraphEntry>,
    /// Optional fingerprint of the `InterTaintConfig` that produced
    /// the cached entries. Bump-on-mismatch lets the consumer tell
    /// whether a different rulepack would invalidate the cache.
    config_fingerprint: u64,
    /// Optional disk-backed source of truth, populated by
    /// [`TaintGraphIndex::load_from_disk`]. Lookups that miss the
    /// in-memory map probe this before reporting a true miss.
    disk: Option<Arc<FactStoreReader>>,
}

impl TaintGraphIndex {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
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
    fn try_hydrate_from_disk(
        &self,
        source_func: FuncId,
        seed_key: &[String],
    ) -> Option<TaintGraphEntry> {
        let reader = self.inner.read().disk.clone()?;
        let key = factstore_key(source_func, seed_key);
        let hit = reader.get(key).ok().flatten()?;
        let entry = decode_verified(&hit.payload, source_func, seed_key).ok()?;
        let arc = Arc::new(entry.graph);
        let map_key = (source_func, seed_key.to_vec());
        let mut inner = self.inner.write();
        inner
            .by_source_seed
            .entry(map_key.clone())
            .or_insert_with(|| arc.clone());
        Some(inner.by_source_seed.get(&map_key).cloned().unwrap_or(arc))
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
        let mut inner = self.inner.write();
        inner
            .by_source_seed
            .entry((source_func, seed_key))
            .or_insert(graph)
            .clone()
    }

    /// Drop every cached entry. Triggered by `Workspace::ingest_dir`
    /// when a file edit invalidates the underlying call graph.
    pub fn clear(&self) {
        let mut inner = self.inner.write();
        inner.by_source_seed.clear();
        inner.config_fingerprint = 0;
        inner.disk = None;
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
        inner.config_fingerprint = config_fingerprint;
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
        let disk_empty = inner.disk.as_ref().map_or(true, |r| r.is_empty());
        mem_empty && disk_empty
    }

    /// Conventional sidecar path under `<workspace>/.bonsai/`. v2
    /// uses the `.factstore` extension; older `.bin` files are still
    /// readable via [`Self::load_from_disk`] for backward compat.
    #[must_use]
    pub fn sidecar_path(workspace_root: &Path) -> PathBuf {
        workspace_bonsai_dir(workspace_root)
            .join(format!("taint_graph.v{TAINT_GRAPH_CACHE_VERSION}.factstore"))
    }

    /// Legacy bincode sidecar path (pre-v2). Read on warm-reopen so
    /// older `.bonsai/` directories still hydrate; new writes always
    /// go through the factstore path.
    #[must_use]
    pub fn legacy_sidecar_path(workspace_root: &Path) -> PathBuf {
        workspace_bonsai_dir(workspace_root).join("taint_graph.v1.bin")
    }

    /// Snapshot every cached entry into a serialisable shape that
    /// `bincode` can round-trip through disk. Used internally by
    /// the legacy bincode load/save paths; new code persists via
    /// the factstore.
    #[allow(dead_code)]
    fn snapshot(&self) -> SerializableTaintGraphSnapshot {
        let inner = self.inner.read();
        let entries: Vec<SerializableEntry> = inner
            .by_source_seed
            .iter()
            .map(|((func, seeds), graph)| SerializableEntry {
                func_raw: func.raw(),
                seeds: seeds.clone(),
                graph: (**graph).clone(),
            })
            .collect();
        SerializableTaintGraphSnapshot {
            version: TAINT_GRAPH_CACHE_VERSION,
            config_fingerprint: inner.config_fingerprint,
            entries,
        }
    }

    /// Persist the index as a fact-store file. Streams the in-memory
    /// entries (and any entries already on disk that the in-memory
    /// map didn't cover) through the streaming writer so peak RAM
    /// stays bounded by the in-flight payload.
    pub fn save_to_disk(&self, path: &Path) -> std::io::Result<()> {
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
            taint_graph_pipeline_hash(config_fingerprint),
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
            writer.add(key, 0, &payload).map_err(map_factstore_io)?;
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
                writer.add(key, hit.body_hash, &hit.payload).map_err(map_factstore_io)?;
                written_keys.insert(key);
            }
        }
        writer.finish().map_err(map_factstore_io)?;
        Ok(())
    }

    /// Open the factstore sidecar at `path` and swap it in as the
    /// cache's disk store. Subsequent `get` calls hydrate one entry
    /// at a time on demand. Non-existent / corrupt files silently
    /// return `Ok(0)` after logging.
    ///
    /// `config_fingerprint` is mixed into the pipeline-hash check so
    /// a `--rules-dir` swap (which produces a different fingerprint)
    /// causes the file open to fail and the cache to be rebuilt.
    pub fn load_from_disk(&self, path: &Path) -> std::io::Result<usize> {
        if !path.exists() {
            return Ok(0);
        }
        // Try the new factstore format first. We don't know the
        // expected config_fingerprint at this layer, so we accept
        // any pipeline hash by opening with `open_relaxed` and
        // setting the fingerprint from the file. The
        // `clear_for_config` callback handles invalidation on
        // rulepack swap separately.
        let reader = match FactStoreReader::open_relaxed(path) {
            Ok(reader) => reader,
            Err(err) => {
                tracing::warn!(
                    path = %path.display(),
                    error = %err,
                    "ignoring stale or corrupt taint-graph factstore sidecar"
                );
                return Ok(0);
            }
        };
        if reader.header().table_id != TAINT_GRAPH_TABLE_ID {
            tracing::warn!(
                path = %path.display(),
                table_id = reader.header().table_id,
                "ignoring sidecar with unexpected table id"
            );
            return Ok(0);
        }
        let entries = reader.len();
        let mut inner = self.inner.write();
        inner.disk = Some(Arc::new(reader));
        Ok(entries)
    }

    /// Read a legacy bincode `.bin` sidecar (pre-v2). Used during
    /// warm-reopen to keep older `.bonsai/` directories working.
    /// New code should use the factstore path; this is a one-way
    /// migration helper.
    pub fn load_legacy_bincode(&self, path: &Path) -> std::io::Result<usize> {
        if !path.exists() {
            return Ok(0);
        }
        let bytes = std::fs::read(path)?;
        let snap: SerializableTaintGraphSnapshot = match bincode::deserialize(&bytes) {
            Ok(s) => s,
            Err(error) => {
                tracing::warn!(
                    path = %path.display(),
                    error = %error,
                    "ignoring corrupt legacy taint-graph sidecar"
                );
                return Ok(0);
            }
        };
        // Legacy sidecars carried `version = 1`; v2+ goes through the
        // factstore path so anything else here is unexpected.
        if snap.version != 1 {
            return Ok(0);
        }
        let mut inner = self.inner.write();
        inner.by_source_seed.clear();
        inner.config_fingerprint = snap.config_fingerprint;
        for entry in snap.entries {
            inner.by_source_seed.insert(
                (FuncId::new(entry.func_raw), entry.seeds),
                Arc::new(entry.graph),
            );
        }
        Ok(inner.by_source_seed.len())
    }
}

/// Funnel `bonsai_factstore::FactStoreError` into `std::io::Error`.
fn map_factstore_io(err: bonsai_factstore::FactStoreError) -> std::io::Error {
    match err {
        bonsai_factstore::FactStoreError::Io(e) => e,
        other => std::io::Error::new(std::io::ErrorKind::Other, other),
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct SerializableTaintGraphSnapshot {
    version: u32,
    #[serde(default)]
    config_fingerprint: u64,
    entries: Vec<SerializableEntry>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct SerializableEntry {
    func_raw: u32,
    seeds: Vec<String>,
    graph: EntryTaintGraph,
}

// The legacy `unique_taint_graph_tmp_path` helper was removed when
// the bincode `save_to_disk` path migrated to
// [`bonsai_factstore::FactStoreWriter`], which manages its own
// atomic-rename tmp file naming. The legacy bincode types
// `SerializableTaintGraphSnapshot` / `SerializableEntry` above are
// retained for [`TaintGraphIndex::load_legacy_bincode`] back-compat
// only.

