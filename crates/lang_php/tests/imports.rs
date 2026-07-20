use bonsai_db::AnalyzerDb;
use bonsai_lang_api::LanguageRegistry;
use bonsai_vfs::Vfs;
use std::sync::Arc;

fn imports_for(source: &str) -> Vec<bonsai_lang_api::ImportSpec> {
    let vfs = Arc::new(Vfs::new());
    let file = vfs.write("entry.php".to_string(), Arc::<str>::from(source));
    let registry = Arc::new(LanguageRegistry::new());
    registry.register(Arc::new(bonsai_lang_php::PhpAdapter::new()));
    AnalyzerDb::new(vfs, registry).imports_for(file)
}

#[test]
fn namespace_use_emits_implicit_local_binding_from_ast() {
    let imports = imports_for("<?php use App\\Middle; use App\\Leaf as L;");

    assert!(imports
        .iter()
        .any(|import| { import.module == "App\\Middle" && import.alias.as_deref() == Some("Middle") }));
    assert!(imports
        .iter()
        .any(|import| import.module == "App\\Leaf" && import.alias.as_deref() == Some("L")));
}

#[test]
fn require_remains_a_side_effect_import_without_local_binding() {
    let imports = imports_for("<?php require_once 'middle.php';");

    assert!(imports
        .iter()
        .any(|import| { import.module == "middle.php" && import.alias.is_none() && import.is_wildcard }));
}
