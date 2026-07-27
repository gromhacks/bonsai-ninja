//! Workspace-level class/method/constructor index.
//!
//! Replaces the per-resolution linear scans of `decls_in(class_file)`
//! at:
//! - `crates/resolve/src/lib.rs::resolve_callable_member_with_context`
//! - `crates/workspace/src/cross_module.rs::collect_method_candidates_for_class_inner`
//! - `crates/workspace/src/cross_module.rs::find_constructor_for_class`
//! - `crates/workspace/src/lib.rs::find_constructor_symbols`
//!
//! Each method-on-class lookup becomes O(1). Built from compact
//! compiler declaration headers on first access; cleared on file edits.

use ahash::AHashMap;
use bonsai_common::{FuncId, SymbolId};
use bonsai_index::{GlobalIndex, GlobalIndexIdentity};
use bonsai_lang_api::DeclKind;
use parking_lot::RwLock;
use std::sync::Arc;

#[derive(Default, Debug)]
pub struct ClassMemberIndex {
    inner: RwLock<Option<(GlobalIndexIdentity, Arc<Built>)>>,
}

#[derive(Default, Debug)]
struct Built {
    /// `(class_sym, method_name) → callable FuncIds`. Each entry is
    /// the candidates the resolver was scanning the class file for.
    methods: AHashMap<(SymbolId, String), Vec<FuncId>>,
    /// `class_sym → constructor FuncId(s)`. All constructors are
    /// retained so caller-side lookup can report overload ambiguity
    /// instead of silently picking a workspace-order winner.
    constructors: AHashMap<SymbolId, Vec<FuncId>>,
}

impl ClassMemberIndex {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Lookup callable methods named `method` declared on
    /// `class_sym`. Returns `&[]` if the class has no such method.
    pub fn methods_of(&self, headers: &GlobalIndex, class_sym: SymbolId, method: &str) -> Vec<FuncId> {
        let built = self.built(headers);
        built
            .methods
            .get(&(class_sym, method.to_string()))
            .cloned()
            .unwrap_or_default()
    }

    /// Lookup `DeclKind::Constructor` decls on `class_sym`.
    pub fn constructors_of(&self, headers: &GlobalIndex, class_sym: SymbolId) -> Vec<FuncId> {
        let built = self.built(headers);
        built.constructors.get(&class_sym).cloned().unwrap_or_default()
    }

    /// Drop every cached entry. Triggered by file edits.
    pub fn clear(&self) {
        *self.inner.write() = None;
    }

    fn built(&self, headers: &GlobalIndex) -> Arc<Built> {
        let identity = headers.identity();
        // Drop the read guard before taking the write lock: parking_lot
        // RwLock is non-reentrant.
        let cached = self
            .inner
            .read()
            .as_ref()
            .filter(|(cached_identity, _)| cached_identity == &identity)
            .map(|(_, built)| Arc::clone(built));
        if let Some(hit) = cached {
            return hit;
        }
        // Build while owning the write slot. Besides making cold access
        // single-flight, this orders edit invalidation after any build that
        // still references the old immutable header snapshot. Building
        // outside the lock allowed `clear()` to run first and the stale
        // builder to repopulate the cache afterward.
        let mut slot = self.inner.write();
        if let Some((_, existing)) = slot
            .as_ref()
            .filter(|(cached_identity, _)| cached_identity == &identity)
        {
            return Arc::clone(existing);
        }
        let mut methods: AHashMap<(SymbolId, String), Vec<FuncId>> = AHashMap::default();
        let mut constructors: AHashMap<SymbolId, Vec<FuncId>> = AHashMap::default();
        for file in headers.all_files() {
            for decl in headers.decls_in(file) {
                let Some(parent) = decl.parent else { continue };
                if !matches!(
                    decl.kind,
                    DeclKind::Function | DeclKind::Method | DeclKind::Constructor
                ) {
                    continue;
                }
                let func = FuncId::new(decl.symbol.raw());
                methods.entry((parent, decl.name.clone())).or_default().push(func);
                if matches!(decl.kind, DeclKind::Constructor) {
                    constructors.entry(parent).or_default().push(func);
                }
            }
        }
        for vec in methods.values_mut() {
            vec.sort_by_key(|f| f.raw());
            vec.dedup();
        }
        for vec in constructors.values_mut() {
            vec.sort_by_key(|f| f.raw());
            vec.dedup();
        }
        let arc = Arc::new(Built {
            methods,
            constructors,
        });
        *slot = Some((identity, arc.clone()));
        arc
    }

    #[must_use]
    pub fn is_built(&self) -> bool {
        self.inner.read().is_some()
    }
}
