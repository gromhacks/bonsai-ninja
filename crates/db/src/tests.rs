use super::*;
use bonsai_lang_api::{AdapterError, LanguageAdapter, LanguageId};
use bonsai_vfs::Vfs;

struct EmptyImportPythonAdapter;

impl LanguageAdapter for EmptyImportPythonAdapter {
    fn language_id(&self) -> LanguageId {
        LanguageId::new("python")
    }

    fn display_name(&self) -> &'static str {
        "Python with empty import index"
    }

    fn file_extensions(&self) -> &'static [&'static str] {
        &["py"]
    }

    fn tree_sitter_language(&self) -> Result<tree_sitter::Language, AdapterError> {
        bonsai_lang_python::PythonAdapter::new().tree_sitter_language()
    }

    fn capabilities(&self) -> bonsai_lang_api::LanguageCapabilities {
        bonsai_lang_api::LanguageCapabilities::unsupported()
    }

    fn extract_declarations(&self, file: FileId, _ctx: &AdapterContext<'_>) -> DeclIndex {
        DeclIndex {
            file,
            ..Default::default()
        }
    }

    fn extract_imports(&self, file: FileId, _ctx: &AdapterContext<'_>) -> ImportIndex {
        ImportIndex {
            file,
            imports: Vec::new(),
        }
    }
}

#[test]
fn imports_for_treats_empty_adapter_index_as_authoritative() {
    let vfs = Arc::new(Vfs::new());
    let file = vfs.write(
        "fixture.py",
        Arc::<str>::from("import os\n\ndef handler():\n    return os.getcwd()\n"),
    );
    let registry = Arc::new(LanguageRegistry::new());
    registry.register(Arc::new(EmptyImportPythonAdapter));
    let db = AnalyzerDb::new(vfs, registry);

    assert!(
        db.imports_for(file).is_empty(),
        "adapter-returned empty imports must not fall through to generic syntax extraction"
    );
}

#[test]
fn configured_idg_services_are_isolated_by_semantic_fingerprint() {
    let db = AnalyzerDb::new(Arc::new(Vfs::new()), Arc::new(LanguageRegistry::new()));
    let service = || {
        Arc::new(bonsai_idg::IdgQueryService::new(
            Arc::new(bonsai_idg::IdgWorkspace::new()),
            Arc::new(bonsai_index::GlobalIndex::new()),
        ))
    };
    let first = service();
    let second = service();

    let cached_first = db.set_idg_service_for_semantics(11, first.clone());
    let cached_second = db.set_idg_service_for_semantics(22, second.clone());
    assert!(Arc::ptr_eq(&cached_first, &first));
    assert!(Arc::ptr_eq(&cached_second, &second));
    assert!(Arc::ptr_eq(
        &db.idg_service_for_semantics(11).expect("first semantics"),
        &first
    ));
    assert!(Arc::ptr_eq(&db.set_idg_service_for_semantics(11, second), &first));

    db.invalidate_idg_service();
    assert!(db.idg_service_for_semantics(11).is_none());
    assert!(db.idg_service_for_semantics(22).is_none());
}
