//! Workspace-cached transitive caller closure on the resolved call
//! graph. Precomputes "every function that can reach `func` within
//! `max_depth` caller hops" so security/analysis can replace its
//! per-invocation BFS with a shared lookup. The set is rulepack-
//! independent — selection by `source_returning_indices` happens
//! after the lookup.
//!
//! The closure is cached lazily on first access. Cleared on file
//! edits via `Workspace::ingest_dir`.

use ahash::{AHashMap, AHashSet};
use bonsai_callgraph::ResolvedCallGraph;
use bonsai_common::FuncId;
use parking_lot::RwLock;
use std::sync::Arc;

type TransitiveCallersMap = AHashMap<(FuncId, u32), Arc<[FuncId]>>;

/// Workspace-wide cache keyed on `(func, max_depth)`. Each entry is
/// the deterministic-ordered transitive caller set for the function
/// at the chosen depth.
#[derive(Default, Debug)]
pub struct TransitiveCallersIndex {
    inner: RwLock<TransitiveCallersMap>,
}

impl TransitiveCallersIndex {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Lookup the transitive caller set for `func` at `max_depth`.
    /// On miss, build using a BFS over the supplied resolved call
    /// graph and cache. The output is sorted by `FuncId.raw()` for
    /// stable downstream finding fingerprints.
    pub fn callers_of(&self, cg: &ResolvedCallGraph, func: FuncId, max_depth: u32) -> Arc<[FuncId]> {
        let key = (func, max_depth);
        // Drop the read guard with `;` before any potential write
        // upgrade — Rust extends temporary lifetimes across an
        // if-let's branches, and `parking_lot` RwLocks deadlock on
        // same-thread read→write. (Same hazard B1 hit.)
        let cached = self.inner.read().get(&key).cloned();
        if let Some(hit) = cached {
            return hit;
        }
        let computed: Arc<[FuncId]> = compute_transitive_callers(cg, func, max_depth).into();
        let mut write = self.inner.write();
        write.entry(key).or_insert(computed).clone()
    }

    /// Drop every cached entry. Triggered by file edits.
    pub fn clear(&self) {
        self.inner.write().clear();
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.read().len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.read().is_empty()
    }
}

fn compute_transitive_callers(cg: &ResolvedCallGraph, start: FuncId, max_depth: u32) -> Vec<FuncId> {
    if max_depth == 0 {
        return Vec::new();
    }
    let mut visited: AHashSet<FuncId> = AHashSet::new();
    visited.insert(start);
    let mut frontier: Vec<FuncId> = vec![start];
    let mut all_callers: Vec<FuncId> = Vec::new();
    for _ in 0..max_depth {
        let mut next: Vec<FuncId> = Vec::new();
        for callee in &frontier {
            // Sort callers so the BFS expansion ordering (and the
            // resulting cached vec) is deterministic regardless of
            // ResolvedCallGraph's internal hash iteration.
            let mut callers: Vec<FuncId> = cg.callers_of(*callee).map(|e| e.from).collect();
            callers.sort_by_key(|f| f.raw());
            callers.dedup();
            for caller in callers {
                if visited.insert(caller) {
                    all_callers.push(caller);
                    next.push(caller);
                }
            }
        }
        if next.is_empty() {
            break;
        }
        frontier = next;
    }
    all_callers.sort_by_key(|f| f.raw());
    all_callers
}
