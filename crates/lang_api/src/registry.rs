//! Adapter registry.
//!
//! Binaries construct a [`LanguageRegistry`] once, register each adapter they
//! want, and hand the registry to the analyzer database. The registry is
//! dispatch-by-extension for now; adapters that need content sniffing should
//! layer it on top.

use crate::{types::LanguageId, DynAdapter, LanguageAdapter};
use ahash::AHashMap;
use parking_lot::RwLock;
use std::sync::Arc;

#[derive(Default)]
pub struct LanguageRegistry {
    inner: RwLock<Inner>,
}

#[derive(Default)]
struct Inner {
    by_id: AHashMap<LanguageId, DynAdapter>,
    by_ext: AHashMap<String, Vec<DynAdapter>>,
}

impl std::fmt::Debug for LanguageRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let inner = self.inner.read();
        f.debug_struct("LanguageRegistry")
            .field("adapters", &inner.by_id.len())
            .finish()
    }
}

/// Shared, cheap-to-clone handle.
pub type AdapterArc = Arc<dyn LanguageAdapter>;

impl LanguageRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an adapter to the registry under both its language id and every
    /// declared file extension.
    pub fn register(&self, adapter: AdapterArc) {
        let mut inner = self.inner.write();
        // Preserve every adapter for ambiguous compiler extensions (`.h` is
        // valid C or C++). Registration order is the deterministic tie-breaker
        // used when both grammars parse a file equally well.
        for ext in adapter.file_extensions() {
            let candidates = inner.by_ext.entry((*ext).to_ascii_lowercase()).or_default();
            if !candidates
                .iter()
                .any(|candidate| candidate.language_id() == adapter.language_id())
            {
                candidates.push(adapter.clone());
            }
        }
        inner.by_id.insert(adapter.language_id(), adapter);
    }

    /// Look up an adapter by file extension. Case-insensitive.
    ///
    /// For an ambiguous extension this returns the first registered adapter;
    /// database-backed source analysis uses [`Self::adapters_for_extension`]
    /// and selects from the complete candidate set using concrete parse facts.
    pub fn adapter_for_extension(&self, ext: &str) -> Option<AdapterArc> {
        self.inner
            .read()
            .by_ext
            .get(&ext.to_ascii_lowercase())
            .and_then(|candidates| candidates.first())
            .cloned()
    }

    /// Every adapter that claims `ext`, in deterministic registration order.
    pub fn adapters_for_extension(&self, ext: &str) -> Vec<AdapterArc> {
        self.inner
            .read()
            .by_ext
            .get(&ext.to_ascii_lowercase())
            .cloned()
            .unwrap_or_default()
    }

    /// Look up an adapter by its registered language id.
    pub fn adapter(&self, id: LanguageId) -> Option<AdapterArc> {
        self.inner.read().by_id.get(&id).cloned()
    }

    /// Snapshot every registered adapter. Order is not stable; callers that
    /// need a deterministic order should sort by `language_id`.
    pub fn all(&self) -> Vec<AdapterArc> {
        self.inner.read().by_id.values().cloned().collect()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.read().by_id.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.read().by_id.is_empty()
    }
}
