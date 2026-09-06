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
use bonsai_lang_api::{Decl, DeclKind};
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

/// Immutable point-query index over compiler declaration spans.
///
/// Consumers that already own a file-local compiler body can build this
/// directly without materializing workspace-global headers. The same
/// range-maximum implementation backs the cached workspace index below, so
/// nested declarations that end before an outer call cannot hide their
/// still-live lexical owner.
#[derive(Debug)]
pub struct EnclosingSpanIndex {
    entries: Arc<Vec<EnclosingEntry>>,
    /// Range-maximum tree over entry end offsets. It lets a point lookup skip
    /// completed nested lambdas and find the still-containing outer
    /// declaration in `O(log declarations)` time.
    max_end_tree: Box<[u64]>,
    leaf_count: usize,
}

impl EnclosingSpanIndex {
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

    /// Build an index containing only executable compiler declarations.
    ///
    /// Security call attribution asks for a callable owner, not the nearest
    /// local struct/type declaration. Filtering here prevents a local type
    /// that ends before a call from erasing the surrounding function.
    #[must_use]
    pub fn from_callable_decls(decls: &[Decl]) -> Self {
        Self::new(
            decls
                .iter()
                .filter(|decl| {
                    matches!(
                        decl.kind,
                        DeclKind::Function | DeclKind::Method | DeclKind::Constructor
                    )
                })
                .map(|decl| EnclosingEntry {
                    start: decl.span.start,
                    end: decl.span.end,
                    name: decl.name.clone(),
                    symbol: decl.symbol,
                })
                .collect(),
        )
    }

    /// Return the innermost indexed declaration covering `pos`.
    /// Same as [`Self::from_callable_decls`] over borrowed declarations.
    #[must_use]
    pub fn from_callable_decl_refs(decls: &[&Decl]) -> Self {
        Self::new(
            decls
                .iter()
                .filter(|decl| {
                    matches!(
                        decl.kind,
                        DeclKind::Function | DeclKind::Method | DeclKind::Constructor
                    )
                })
                .map(|decl| EnclosingEntry {
                    start: decl.span.start,
                    end: decl.span.end,
                    name: decl.name.clone(),
                    symbol: decl.symbol,
                })
                .collect(),
        )
    }

    #[must_use]
    pub fn enclosing(&self, pos: u64) -> Option<EnclosingEntry> {
        let upper = self.entries.partition_point(|entry| entry.start <= pos);
        let index = self.rightmost_covering(1, 0, self.leaf_count, upper, pos)?;
        self.entries.get(index).cloned()
    }

    /// Find the innermost declaration containing the complete half-open
    /// range. A zero-width range is a point query. Reusing the range-maximum
    /// tree lets a range that crosses an inner declaration's end find its
    /// outer owner without scanning every declaration.
    #[must_use]
    pub fn enclosing_range(&self, start: u64, end: u64) -> Option<EnclosingEntry> {
        if end < start {
            return None;
        }
        let last = end.saturating_sub(1).max(start);
        let upper = self.entries.partition_point(|entry| entry.start <= start);
        let index = self.rightmost_covering(1, 0, self.leaf_count, upper, last)?;
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
    files: AHashMap<FileId, Arc<EnclosingSpanIndex>>,
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

    fn index_for(&self, headers: &GlobalIndex, file: FileId) -> Arc<EnclosingSpanIndex> {
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
        let index = Arc::new(EnclosingSpanIndex::new(build_entries(headers, file)));
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
        // The complete declaration span (signature and body): a position in
        // a parameter list or on the name belongs to that callable too.
        .map(|d| EnclosingEntry {
            start: d.span.start,
            end: d.span.end,
            name: d.name.clone(),
            symbol: d.symbol,
        })
        .collect();
    entries
}
