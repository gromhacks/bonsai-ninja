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
