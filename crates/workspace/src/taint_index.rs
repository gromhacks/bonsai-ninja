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

use ahash::AHashMap;
use bonsai_common::{workspace_bonsai_dir, FuncId};
use bonsai_taint::EntryTaintGraph;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

/// On-disk snapshot version for the workspace-wide taint graph.
/// Bump when the snapshot shape changes so older sidecars are
/// rejected.
pub const TAINT_GRAPH_CACHE_VERSION: u32 = 1;

static TAINT_GRAPH_TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

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
}

impl TaintGraphIndex {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Look up a cached graph; `None` means "miss, you build it."
    #[must_use]
    pub fn get(&self, source_func: FuncId, seed_key: &[String]) -> Option<TaintGraphEntry> {
        let inner = self.inner.read();
        inner
            .by_source_seed
            .get(&(source_func, seed_key.to_vec()))
            .cloned()
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

    /// Number of cached graph entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.read().by_source_seed.len()
    }

    /// True iff the cache is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.read().by_source_seed.is_empty()
    }

    /// Conventional sidecar path under `<workspace>/.bonsai/`.
    #[must_use]
    pub fn sidecar_path(workspace_root: &Path) -> PathBuf {
        workspace_bonsai_dir(workspace_root)
            .join(format!("taint_graph.v{TAINT_GRAPH_CACHE_VERSION}.bin"))
    }

    /// Snapshot every cached entry into a serialisable shape that
    /// `bincode` can round-trip through disk.
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

    /// Persist the index as a versioned bincode blob. Atomic-rename
    /// so a half-written sidecar can't survive a process kill.
    pub fn save_to_disk(&self, path: &Path) -> std::io::Result<()> {
        let snap = self.snapshot();
        let bytes = bincode::serialize(&snap)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        let tmp = unique_taint_graph_tmp_path(path);
        {
            use std::io::Write;
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&tmp)?;
            f.write_all(&bytes)?;
            f.sync_all()?;
        }
        if let Err(err) = std::fs::rename(&tmp, path) {
            let _ = std::fs::remove_file(&tmp);
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

    /// Load entries from a sidecar produced by `save_to_disk`.
    /// Returns the number of entries that survived schema validation.
    /// Non-existent sidecar returns `Ok(0)` — nothing to load is not
    /// an error. Version mismatch and corrupt blobs return `Ok(0)`
    /// after logging via `tracing`.
    pub fn load_from_disk(&self, path: &Path) -> std::io::Result<usize> {
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
                    "ignoring corrupt taint-graph sidecar"
                );
                return Ok(0);
            }
        };
        if snap.version != TAINT_GRAPH_CACHE_VERSION {
            tracing::warn!(
                version = snap.version,
                expected = TAINT_GRAPH_CACHE_VERSION,
                "ignoring taint-graph sidecar with mismatched version"
            );
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

fn unique_taint_graph_tmp_path(target: &Path) -> PathBuf {
    use std::ffi::OsString;
    let counter = TAINT_GRAPH_TMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    let mut name = OsString::from(".taint_graph-tmp-");
    name.push(pid.to_string());
    name.push("-");
    name.push(counter.to_string());
    let mut path = target.to_path_buf();
    path.set_file_name(name);
    path
}
