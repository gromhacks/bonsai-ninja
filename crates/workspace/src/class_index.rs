//! Workspace-level class/method/constructor index.
//!
//! Replaces the per-resolution linear scans of `decls_in(class_file)`
//! at:
//! - `crates/resolve/src/lib.rs::resolve_callable_member_with_context`
//! - `crates/workspace/src/cross_module.rs::collect_method_candidates_for_class_inner`
//! - `crates/workspace/src/cross_module.rs::find_constructor_for_class`
//! - `crates/workspace/src/lib.rs::find_constructor_symbols`
//!
//! Each method-on-class lookup becomes O(1). Built from the global
//! index on first access; cleared on file edits.

use ahash::AHashMap;
use bonsai_common::{FuncId, SymbolId};
use bonsai_db::AnalyzerDb;
use bonsai_lang_api::DeclKind;
use parking_lot::RwLock;
use std::sync::Arc;

#[derive(Default, Debug)]
pub struct ClassMemberIndex {
    inner: RwLock<Option<Arc<Built>>>,
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
    pub fn methods_of(&self, db: &AnalyzerDb, class_sym: SymbolId, method: &str) -> Vec<FuncId> {
        let built = self.built(db);
        built
            .methods
            .get(&(class_sym, method.to_string()))
            .cloned()
            .unwrap_or_default()
    }

    /// Lookup `DeclKind::Constructor` decls on `class_sym`.
    pub fn constructors_of(&self, db: &AnalyzerDb, class_sym: SymbolId) -> Vec<FuncId> {
        let built = self.built(db);
        built.constructors.get(&class_sym).cloned().unwrap_or_default()
    }

    /// Drop every cached entry. Triggered by file edits.
    pub fn clear(&self) {
        *self.inner.write() = None;
    }

    fn built(&self, db: &AnalyzerDb) -> Arc<Built> {
        // Drop the read guard's temporary before the write upgrade
        // below — parking_lot RwLock is non-reentrant.
        let cached = self.inner.read().clone();
        if let Some(hit) = cached {
            return hit;
        }
        let mut methods: AHashMap<(SymbolId, String), Vec<FuncId>> = AHashMap::default();
        let mut constructors: AHashMap<SymbolId, Vec<FuncId>> = AHashMap::default();
        let global = db.global_index();
        for file in global.all_files() {
            for decl in global.decls_in(file) {
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
        let mut slot = self.inner.write();
        if let Some(existing) = slot.clone() {
            return existing;
        }
        *slot = Some(arc.clone());
        arc
    }

    #[must_use]
    pub fn is_built(&self) -> bool {
        self.inner.read().is_some()
    }
}
