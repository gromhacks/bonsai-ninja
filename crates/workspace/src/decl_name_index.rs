//! Workspace-level decl-name index. Caches every decl's lowercased
//! name once per workspace lifetime so `inspect --query <pat>` does a
//! single sweep over a precomputed table instead of re-walking
//! `global.decls_in(file)` per file per query.
//!
//! `Contains` queries pay a single `lowercased_name.contains(needle)`
//! per entry; `Regex` queries fall through to the original name. The
//! cache is workspace-wide; rebuilt on demand and cleared on edit.

use bonsai_db::AnalyzerDb;
use bonsai_lang_api::Decl;
use parking_lot::RwLock;
use std::sync::Arc;

#[derive(Clone, Debug)]
pub struct DeclNameEntry {
    pub lowercased_name: String,
    pub decl: Decl,
}

#[derive(Default, Debug)]
pub struct DeclNameIndex {
    inner: RwLock<Option<Arc<Vec<DeclNameEntry>>>>,
}

impl DeclNameIndex {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Snapshot of every decl in the workspace, with lowercased
    /// names precomputed. Built lazily on first access.
    pub fn entries(&self, db: &AnalyzerDb) -> Arc<Vec<DeclNameEntry>> {
        // Drop the read guard's temporary before the write upgrade.
        let cached = self.inner.read().clone();
        if let Some(hit) = cached {
            return hit;
        }
        let global = db.global_index();
        let mut out: Vec<DeclNameEntry> = Vec::new();
        for file in global.all_files() {
            for decl in global.decls_in(file) {
                let lowercased_name = decl.name.to_lowercase();
                out.push(DeclNameEntry {
                    lowercased_name,
                    decl: decl.clone(),
                });
            }
        }
        let arc = Arc::new(out);
        let mut slot = self.inner.write();
        if let Some(existing) = slot.clone() {
            return existing;
        }
        *slot = Some(arc.clone());
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
