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
use bonsai_index::{GlobalIndex, GlobalIndexIdentity};
use parking_lot::RwLock;
use std::cmp::Reverse;
use std::sync::Arc;

/// One entry in the per-file enclosing-decl array.
#[derive(Clone, Debug)]
pub struct EnclosingEntry {
    pub start: u64,
    pub end: u64,
    pub name: String,
    pub symbol: bonsai_common::SymbolId,
}

#[derive(Debug)]
struct EnclosingFileIndex {
    entries: Arc<Vec<EnclosingEntry>>,
    /// Range-maximum tree over entry end offsets. It lets a point lookup skip
    /// completed nested lambdas and find the still-containing outer
    /// declaration in `O(log declarations)` time.
    max_end_tree: Box<[u64]>,
    leaf_count: usize,
}

impl EnclosingFileIndex {
    fn new(mut entries: Vec<EnclosingEntry>) -> Self {
        // For equal starts, put the narrowest interval last so the rightmost
        // containing lookup returns the innermost compiler declaration.
        entries.sort_unstable_by_key(|entry| (entry.start, Reverse(entry.end)));
        let leaf_count = entries.len().next_power_of_two().max(1);
        let mut max_end_tree = vec![0_u64; leaf_count.saturating_mul(2)];
        for (index, entry) in entries.iter().enumerate() {
            max_end_tree[leaf_count + index] = entry.end;
        }
        for node in (1..leaf_count).rev() {
            max_end_tree[node] = max_end_tree[node * 2].max(max_end_tree[node * 2 + 1]);
        }
        Self {
            entries: Arc::new(entries),
            max_end_tree: max_end_tree.into_boxed_slice(),
            leaf_count,
        }
    }

    fn enclosing(&self, pos: u64) -> Option<EnclosingEntry> {
        let upper = self.entries.partition_point(|entry| entry.start <= pos);
        let index = self.rightmost_covering(1, 0, self.leaf_count, upper, pos)?;
        self.entries.get(index).cloned()
    }

    fn rightmost_covering(
        &self,
        node: usize,
        start: usize,
        end: usize,
        upper: usize,
        pos: u64,
    ) -> Option<usize> {
        if start >= upper || self.max_end_tree.get(node).copied().unwrap_or_default() <= pos {
            return None;
        }
        if end - start == 1 {
            return (start < self.entries.len()).then_some(start);
        }
        let middle = start + (end - start) / 2;
        self.rightmost_covering(node * 2 + 1, middle, end, upper, pos)
            .or_else(|| self.rightmost_covering(node * 2, start, middle, upper, pos))
    }
}

#[derive(Default, Debug)]
struct EnclosingIndexState {
    identity: Option<GlobalIndexIdentity>,
    files: AHashMap<FileId, Arc<EnclosingFileIndex>>,
}

#[derive(Default, Debug)]
pub struct EnclosingIndex {
    inner: RwLock<EnclosingIndexState>,
}

impl EnclosingIndex {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Look up the innermost decl whose body covers `pos` in `file`.
    /// Builds the per-file interval index on first access.
    pub fn enclosing_for(&self, headers: &GlobalIndex, file: FileId, pos: u64) -> Option<EnclosingEntry> {
        self.index_for(headers, file).enclosing(pos)
    }

    /// Just the name of the enclosing decl; convenience for
    /// callers that already have a position-only query path.
    pub fn enclosing_name(&self, headers: &GlobalIndex, file: FileId, pos: u64) -> Option<String> {
        self.enclosing_for(headers, file, pos).map(|e| e.name)
    }

    /// Per-file sorted entry list.
    pub fn entries_for(&self, headers: &GlobalIndex, file: FileId) -> Arc<Vec<EnclosingEntry>> {
        Arc::clone(&self.index_for(headers, file).entries)
    }

    fn index_for(&self, headers: &GlobalIndex, file: FileId) -> Arc<EnclosingFileIndex> {
        let identity = headers.identity();
        // Drop the read guard's temporary before the write upgrade.
        let cached = {
            let state = self.inner.read();
            (state.identity.as_ref() == Some(&identity))
                .then(|| state.files.get(&file).cloned())
                .flatten()
        };
        if let Some(hit) = cached {
            return hit;
        }
        // Keep construction ordered with per-file invalidation. Building
        // outside the write lock let an old compiler-header snapshot insert
        // after an edit had already removed the prior entry.
        let mut state = self.inner.write();
        if state.identity.as_ref() != Some(&identity) {
            state.files.clear();
            state.identity = Some(identity);
        }
        if let Some(existing) = state.files.get(&file).cloned() {
            return existing;
        }
        let index = Arc::new(EnclosingFileIndex::new(build_entries(headers, file)));
        state.files.insert(file, Arc::clone(&index));
        index
    }

    /// Drop a single file's cached array. Workspace edit paths call
    /// this so subsequent queries rebuild.
    pub fn invalidate_file(&self, file: FileId) {
        self.inner.write().files.remove(&file);
    }

    /// Drop every cached entry — used at workspace open or by the
    /// coarse `clear` path.
    pub fn clear(&self) {
        let mut state = self.inner.write();
        state.files.clear();
        state.identity = None;
    }

    #[must_use]
    pub fn is_built_for(&self, file: FileId) -> bool {
        self.inner.read().files.contains_key(&file)
    }
}

fn build_entries(headers: &GlobalIndex, file: FileId) -> Vec<EnclosingEntry> {
    let entries: Vec<EnclosingEntry> = headers
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
    entries
}
