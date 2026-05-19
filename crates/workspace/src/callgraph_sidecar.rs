//! `.bonsai/callgraph.v10.bin` sidecar — persists the workspace's
//! resolved call graph across CLI invocations. Earlier every
//! `bonsai-ninja` command rebuilt it from scratch (sequential
//! `for file in global.all_files()` loop in
//! `bonsai_callgraph::ResolvedCallGraph::build_with_file_info`).
//! For an OWASP-scale workspace the rebuild is several seconds per
//! command; chained `sources → taint-analysis → inspect` workflows
//! pay it three times.
//!
//! Invalidation: same shape as `dataflow.v2.bin`. Each entry in
//! `files` carries a `(path, content_hash)` pair; on load we
//! verify every workspace file in the cached snapshot matches a
//! current file with the same hash. Any mismatch (file changed,
//! file removed, file added) drops the sidecar.

use crate::cache_fingerprint::dependency_metadata_fingerprint_for_sidecar;
use ahash::AHashMap;
use bonsai_callgraph::ResolvedCallGraph;
use bonsai_common::{workspace_bonsai_dir, MATCHER_POLICY_FINGERPRINT};
use bonsai_db::AnalyzerDb;
use bonsai_hash::fnv1a_bytes64;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

pub const CALLGRAPH_CACHE_VERSION: u32 = 10;
static CALLGRAPH_TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct CallgraphSnapshot {
    pub version: u32,
    /// Matcher policy fingerprint at save time. A bump in
    /// `MATCHER_POLICY_FINGERPRINT` invalidates the sidecar even
    /// when content hashes match.
    pub matcher_policy_fingerprint: u128,
    /// `(workspace-relative-path, content_hash)` pairs for every
    /// workspace file that contributed to the graph at save time.
    pub files: Vec<(String, u64)>,
    /// Fingerprint of dependency manifests and lockfiles that may
    /// influence import and call resolution.
    pub dependency_metadata_fingerprint: u64,
    pub graph: ResolvedCallGraph,
}

#[must_use]
pub fn callgraph_sidecar_path(workspace_root: &Path) -> PathBuf {
    workspace_bonsai_dir(workspace_root).join(format!("callgraph.v{CALLGRAPH_CACHE_VERSION}.bin"))
}

pub(crate) fn save_callgraph_sidecar(
    path: &Path,
    db: &AnalyzerDb,
    graph: &ResolvedCallGraph,
) -> std::io::Result<()> {
    let mut files: Vec<(String, u64)> = Vec::new();
    for file in db.vfs().all_files() {
        let Ok(snapshot) = db.vfs().snapshot(file) else {
            continue;
        };
        let Ok(path) = db.vfs().path(file) else {
            continue;
        };
        let path_string = path.to_string_lossy().into_owned();
        let hash = fnv1a_bytes64(snapshot.text.as_bytes());
        files.push((path_string, hash));
    }
    files.sort();
    let snap = CallgraphSnapshot {
        version: CALLGRAPH_CACHE_VERSION,
        matcher_policy_fingerprint: MATCHER_POLICY_FINGERPRINT,
        files,
        dependency_metadata_fingerprint: dependency_metadata_fingerprint_for_sidecar(path),
        graph: graph.clone(),
    };
    let bytes =
        bincode::serialize(&snap).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let tmp = unique_tmp_path(path);
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
    Ok(())
}

/// Load the sidecar at `path` and return the graph if every
/// recorded `(path, content_hash)` pair still matches the current
/// workspace state, the schema version matches, and the matcher
/// policy fingerprint matches. Otherwise return `None`.
pub(crate) fn load_callgraph_sidecar(path: &Path, db: &AnalyzerDb) -> Option<ResolvedCallGraph> {
    if !path.exists() {
        return None;
    }
    let bytes = std::fs::read(path).ok()?;
    let snap: CallgraphSnapshot = bincode::deserialize(&bytes).ok()?;
    if snap.version != CALLGRAPH_CACHE_VERSION {
        return None;
    }
    if snap.matcher_policy_fingerprint != MATCHER_POLICY_FINGERPRINT {
        return None;
    }
    if snap.dependency_metadata_fingerprint != dependency_metadata_fingerprint_for_sidecar(path) {
        return None;
    }
    // Build the current `(path, hash)` set so we can match it
    // against the snapshot. Any mismatch drops the sidecar — the
    // call graph would otherwise reference stale FuncIds.
    let mut current: AHashMap<String, u64> = AHashMap::new();
    for file in db.vfs().all_files() {
        let Ok(snapshot) = db.vfs().snapshot(file) else {
            continue;
        };
        let Ok(p) = db.vfs().path(file) else {
            continue;
        };
        current.insert(
            p.to_string_lossy().into_owned(),
            fnv1a_bytes64(snapshot.text.as_bytes()),
        );
    }
    if current.len() != snap.files.len() {
        return None;
    }
    for (path_string, hash) in &snap.files {
        match current.get(path_string) {
            Some(current_hash) if current_hash == hash => continue,
            _ => return None,
        }
    }
    Some(snap.graph)
}

fn unique_tmp_path(target: &Path) -> PathBuf {
    use std::ffi::OsString;
    let counter = CALLGRAPH_TMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    let mut name = OsString::from(".callgraph-tmp-");
    name.push(pid.to_string());
    name.push("-");
    name.push(counter.to_string());
    let mut path = target.to_path_buf();
    path.set_file_name(name);
    path
}
