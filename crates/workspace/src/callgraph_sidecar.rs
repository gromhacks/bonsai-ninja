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
use bonsai_common::{workspace_bonsai_dir, write_atomic_bytes, MATCHER_POLICY_FINGERPRINT};
use bonsai_db::AnalyzerDb;
use bonsai_hash::fnv1a_bytes64;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

// v11 (2026-05-27): adapter decl-extraction changes add synthesized
// members (C# expression-bodied-property getters + record members, Java
// records, Solidity struct-literal field writes) → new call edges, so
// callgraphs persisted by older binaries are no longer equivalent.
pub const CALLGRAPH_CACHE_VERSION: u32 = 11;

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
    /// Build-time analyzer fingerprint (git HEAD + dirty-tree hash,
    /// emitted by `crates/workspace/build.rs`). Folded into every
    /// other sidecar's `pipeline_hash` and validated here on load so
    /// an upgraded binary can't reuse a callgraph built by a
    /// different analyzer version — closes the manual-bump foot-gun.
    /// Defaults to `0` for legacy snapshots (validates them out via
    /// version mismatch anyway).
    #[serde(default)]
    pub build_fingerprint: u64,
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
        build_fingerprint: crate::build_fingerprint_hash(),
        graph: graph.clone(),
    };
    let bytes =
        bincode::serialize(&snap).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    write_atomic_bytes(path, &bytes)
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
    if snap.build_fingerprint != crate::build_fingerprint_hash() {
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

/// Validate that a callgraph sidecar is structurally readable and was
/// produced by the current callgraph/matcher/build pipeline. This does not
/// compare workspace source hashes; callers combine it with their manifest
/// source/dependency freshness checks or use
/// [`Workspace::load_callgraph_sidecar`](crate::Workspace::load_callgraph_sidecar)
/// when an [`AnalyzerDb`] is available.
pub fn validate_callgraph_sidecar_file(path: &Path) -> std::io::Result<usize> {
    let bytes = std::fs::read(path)?;
    let snap: CallgraphSnapshot = bincode::deserialize(&bytes)
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))?;
    validate_snapshot_metadata(path, &snap)?;
    Ok(snap.graph.inner().edges.len())
}

/// Validate that a callgraph sidecar is structurally readable, was produced
/// by the current pipeline, and was written for the exact source path/hash
/// set currently on disk.
pub fn validate_callgraph_sidecar_file_with_source_fingerprints<I, P>(
    path: &Path,
    fingerprints: I,
) -> std::io::Result<usize>
where
    I: IntoIterator<Item = (P, u64)>,
    P: AsRef<Path>,
{
    let bytes = std::fs::read(path)?;
    let snap: CallgraphSnapshot = bincode::deserialize(&bytes)
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))?;
    validate_snapshot_metadata(path, &snap)?;
    let mut current: Vec<(String, u64)> = fingerprints
        .into_iter()
        .map(|(path, hash)| (path.as_ref().display().to_string(), hash))
        .collect();
    current.sort();
    if current != snap.files {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "callgraph sidecar source fingerprint mismatch",
        ));
    }
    Ok(snap.graph.inner().edges.len())
}

fn validate_snapshot_metadata(path: &Path, snap: &CallgraphSnapshot) -> std::io::Result<()> {
    if snap.version != CALLGRAPH_CACHE_VERSION {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "callgraph sidecar version mismatch: file={} expected={}",
                snap.version, CALLGRAPH_CACHE_VERSION
            ),
        ));
    }
    if snap.matcher_policy_fingerprint != MATCHER_POLICY_FINGERPRINT {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "callgraph sidecar matcher policy fingerprint mismatch",
        ));
    }
    if snap.dependency_metadata_fingerprint != dependency_metadata_fingerprint_for_sidecar(path) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "callgraph sidecar dependency metadata fingerprint mismatch",
        ));
    }
    if snap.build_fingerprint != crate::build_fingerprint_hash() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "callgraph sidecar build fingerprint mismatch",
        ));
    }
    Ok(())
}
