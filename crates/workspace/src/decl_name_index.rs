//! Workspace-level decl-name index. Caches every decl's lowercased
//! name once per workspace lifetime so `inspect --query <pat>` does a
//! single sweep over a precomputed table instead of re-walking
//! `global.decls_in(file)` per file per query.
//!
//! `Contains` queries pay a single `lowercased_name.contains(needle)`
//! per entry; `Regex` queries fall through to the original name. The
//! cache is workspace-wide; rebuilt on demand and cleared on edit.

use bonsai_index::{GlobalIndex, GlobalIndexIdentity};
use bonsai_lang_api::Decl;
use parking_lot::RwLock;
use std::sync::Arc;

#[derive(Clone, Debug)]
pub struct DeclNameEntry {
    pub lowercased_name: String,
    pub lowercased_qualified_name: Option<String>,
    pub decl: Decl,
}

#[derive(Default, Debug)]
pub struct DeclNameIndex {
    inner: RwLock<Option<(GlobalIndexIdentity, Arc<Vec<DeclNameEntry>>)>>,
}

impl DeclNameIndex {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Snapshot of every decl in the workspace, with lowercased
    /// names precomputed. Built lazily on first access.
    pub fn entries(&self, headers: &GlobalIndex) -> Arc<Vec<DeclNameEntry>> {
        let identity = headers.identity();
        // Drop the read guard's temporary before the write upgrade.
        let cached = self
            .inner
            .read()
            .as_ref()
            .filter(|(cached_identity, _)| cached_identity == &identity)
            .map(|(_, entries)| Arc::clone(entries));
        if let Some(hit) = cached {
            return hit;
        }
        // Serialize the one workspace scan with invalidation. Otherwise an
        // old header snapshot could finish after `clear()` and become the
        // cache visible to queries in the new source generation.
        let mut slot = self.inner.write();
        if let Some((_, existing)) = slot
            .as_ref()
            .filter(|(cached_identity, _)| cached_identity == &identity)
        {
            return Arc::clone(existing);
        }
        let mut out: Vec<DeclNameEntry> = Vec::new();
        for file in headers.all_files() {
            for decl in headers.decls_in(file) {
                let lowercased_name = decl.name.to_lowercase();
                let lowercased_qualified_name = decl.qualified_name.as_ref().map(|name| name.to_lowercase());
                out.push(DeclNameEntry {
                    lowercased_name,
                    lowercased_qualified_name,
                    decl: decl.clone(),
                });
            }
        }
        let arc = Arc::new(out);
        *slot = Some((identity, arc.clone()));
        arc
    }

    /// Drop every cached entry. Triggered by file edits.
    pub fn clear(&self) {
        *self.inner.write() = None;
    }

    #[must_use]
    pub fn is_built(&self) -> bool {
        self.inner.read().is_some()
    }
}
