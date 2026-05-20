use bonsai_db::AnalyzerDb;
use bonsai_lang_api::{LanguageAdapter, LanguageRegistry};
use bonsai_vfs::Vfs;
use std::sync::Arc;

fn db_for(source: &str) -> AnalyzerDb {
    let vfs = Arc::new(Vfs::new());
    vfs.write("main.dart".to_string(), Arc::<str>::from(source));
    let registry = Arc::new(LanguageRegistry::new());
    let adapter: Arc<dyn LanguageAdapter> = Arc::new(bonsai_lang_dart::DartAdapter::new());
    registry.register(adapter);
    let db = AnalyzerDb::new(vfs, registry);
    for file in db.vfs().all_files() {
        let _ = db.decl_index(file);
    }
    db
}

#[test]
fn required_named_parameter_uses_binding_name() {
    let db = db_for("void helper({required String name}) { sink(name); }\n");
    let index = db.global_index();
    let helper = index
        .all_files()
        .flat_map(|file| index.decls_in(file))
        .find(|decl| decl.name == "helper")
        .expect("helper declaration should index");

    assert_eq!(helper.params, vec!["name"]);
}
