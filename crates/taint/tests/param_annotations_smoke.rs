//! P0.5: param_annotations is populated by the kit's
//! `extract_param_annotations` for Java/Kotlin/C# patterns
//! (`formal_parameter > modifiers > marker_annotation / annotation` and
//! `parameter > attribute_list > attribute`). Audit-script literal-
//! string match was the only gap; this test asserts the field is
//! genuinely populated end-to-end.

use bonsai_db::AnalyzerDb;
use bonsai_lang_api::{LanguageAdapter, LanguageRegistry};
use bonsai_vfs::Vfs;
use std::sync::Arc;

fn ws(adapter: Arc<dyn LanguageAdapter>, files: &[(&str, &str)]) -> AnalyzerDb {
    let vfs = Arc::new(Vfs::new());
    for (path, source) in files {
        vfs.write((*path).to_string(), Arc::<str>::from(*source));
    }
    let registry = Arc::new(LanguageRegistry::new());
    registry.register(adapter);
    let db = AnalyzerDb::new(vfs, registry);
    for f in db.vfs().all_files() {
        let _ = db.decl_index(f);
    }
    db
}

fn first_decl_with_annotations(db: &AnalyzerDb) -> Vec<Vec<String>> {
    let g = db.global_index();
    for file in g.all_files() {
        for decl in g.decls_in(file) {
            if decl.param_annotations.iter().any(|anns| !anns.is_empty()) {
                return decl.param_annotations.clone();
            }
        }
    }
    Vec::new()
}

#[test]
fn java_request_body_annotation_populates() {
    let src = "
class Controller {
    void handle(@RequestBody String body, @PathVariable Long id) { sink(body); }
}
";
    let db = ws(
        Arc::new(bonsai_lang_java::JavaAdapter::new()),
        &[("Controller.java", src)],
    );
    let anns = first_decl_with_annotations(&db);
    assert!(
        anns.iter().any(|a| a.iter().any(|n| n == "RequestBody")),
        "Java @RequestBody must populate param_annotations; got {anns:?}"
    );
}

#[test]
fn kotlin_request_body_annotation_populates() {
    let src = "
class Controller {
    fun handle(@RequestBody body: String) { sink(body) }
}
";
    let db = ws(
        Arc::new(bonsai_lang_kotlin::KotlinAdapter::new()),
        &[("Controller.kt", src)],
    );
    let anns = first_decl_with_annotations(&db);
    assert!(
        anns.iter().any(|a| a.iter().any(|n| n == "RequestBody")),
        "Kotlin @RequestBody must populate param_annotations; got {anns:?}"
    );
}

#[test]
fn csharp_from_body_attribute_populates() {
    let src = "
class Controller {
    public void Handle([FromBody] string body) { Sink(body); }
}
";
    let db = ws(
        Arc::new(bonsai_lang_csharp::CSharpAdapter::new()),
        &[("Controller.cs", src)],
    );
    let anns = first_decl_with_annotations(&db);
    assert!(
        anns.iter().any(|a| a.iter().any(|n| n == "FromBody")),
        "C# [FromBody] must populate param_annotations; got {anns:?}"
    );
}
