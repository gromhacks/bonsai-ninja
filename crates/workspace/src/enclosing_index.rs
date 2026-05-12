//! Workspace-level enclosing-decl span index.
//!
//! Replaces per-consumer linear scans in
//! `crates/inspect/src/chain_cache.rs::find_enclosing_func`,
//! `crates/browse/src/common.rs::Locator::from_span`, and any other
//! "given a position, what decl contains it?" caller. Each file's
//! decl bodies sort by start span once; subsequent lookups are
//! `O(log decls in file)`.

use ahash::AHashMap;
use bonsai_common::FileId;
use bonsai_db::AnalyzerDb;
use parking_lot::RwLock;
use std::sync::Arc;

/// One entry in the per-file enclosing-decl array. Sorted by
/// `body.start` so binary search finds the rightmost decl whose
/// body covers a queried position. Decl bodies in a single file
/// never overlap at the same start.
#[derive(Clone, Debug)]
pub struct EnclosingEntry {
    pub start: u64,
    pub end: u64,
    pub name: String,
    pub symbol: bonsai_common::SymbolId,
}

#[derive(Default, Debug)]
pub struct EnclosingIndex {
    inner: RwLock<AHashMap<FileId, Arc<Vec<EnclosingEntry>>>>,
}

impl EnclosingIndex {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Look up the innermost decl whose body covers `pos` in `file`.
    /// Builds the per-file array on first access.
    pub fn enclosing_for(&self, db: &AnalyzerDb, file: FileId, pos: u64) -> Option<EnclosingEntry> {
        let entries = self.entries_for(db, file);
        if entries.is_empty() {
            return None;
        }
        let partition = entries.partition_point(|entry| entry.start <= pos);
        if partition == 0 {
            return None;
        }
        let entry = &entries[partition - 1];
        if pos < entry.end {
            Some(entry.clone())
        } else {
            None
        }
    }

    /// Just the name of the enclosing decl; convenience for
    /// callers that already have a position-only query path.
    pub fn enclosing_name(&self, db: &AnalyzerDb, file: FileId, pos: u64) -> Option<String> {
        self.enclosing_for(db, file, pos).map(|e| e.name)
    }

    /// Per-file sorted entry list.
    pub fn entries_for(&self, db: &AnalyzerDb, file: FileId) -> Arc<Vec<EnclosingEntry>> {
        // Drop the read guard's temporary before the write upgrade.
        let cached = self.inner.read().get(&file).cloned();
        if let Some(hit) = cached {
            return hit;
        }
        let entries = build_entries(db, file);
        let arc = Arc::new(entries);
        let mut inner = self.inner.write();
        if let Some(existing) = inner.get(&file).cloned() {
            return existing;
        }
        inner.insert(file, arc.clone());
        arc
    }

    /// Drop a single file's cached array. Workspace edit paths call
    /// this so subsequent queries rebuild.
    pub fn invalidate_file(&self, file: FileId) {
        self.inner.write().remove(&file);
    }

    /// Drop every cached entry — used at workspace open or by the
    /// coarse `clear` path.
    pub fn clear(&self) {
        self.inner.write().clear();
    }

    #[must_use]
    pub fn is_built_for(&self, file: FileId) -> bool {
        self.inner.read().contains_key(&file)
    }
}

fn build_entries(db: &AnalyzerDb, file: FileId) -> Vec<EnclosingEntry> {
    let global = db.global_index();
    let mut entries: Vec<EnclosingEntry> = global
        .decls_in(file)
        .iter()
        .map(|d| {
            let body = d.body_span.unwrap_or(d.span);
            EnclosingEntry {
                start: body.start,
                end: body.end,
                name: d.name.clone(),
                symbol: d.symbol,
            }
        })
        .collect();
    entries.sort_unstable_by_key(|e| e.start);
    entries
}
