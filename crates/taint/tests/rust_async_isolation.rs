//! Rust async-block flow is syntax-driven. The adapter exposes calls inside an
//! async argument without recognizing scheduler/library names; the rulepack
//! remains the only owner of third-party API identities.

use bonsai_common::FuncId;
use bonsai_db::AnalyzerDb;
use bonsai_lang_api::{LanguageAdapter, LanguageRegistry};
use bonsai_taint::{interprocedural_taint, InterTaintConfig, TokenSet};
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

fn func(db: &AnalyzerDb, name: &str) -> FuncId {
    let g = db.global_index();
    *bonsai_resolve::resolve_callable(&g, name)
        .first()
        .expect("function exists")
}

fn config() -> InterTaintConfig {
    InterTaintConfig::default()
}

fn seed(names: &[&str]) -> TokenSet {
    names.iter().map(|n| (*n).to_string()).collect()
}

#[test]
fn arbitrary_async_argument_body_preserves_taint_without_api_special_cases() {
    let src = r#"
async fn entry(tainted: String, also_clean: String) {
    any_scheduler(async move {
        sink(tainted);
    });
    sink(also_clean);
}
"#;
    let db = ws(Arc::new(bonsai_lang_rust::RustAdapter::new()), &[("m.rs", src)]);
    let entry = func(&db, "entry");
    let result = interprocedural_taint(entry, &seed(&["tainted"]), &config(), &db);
    let sink_taints: Vec<_> = result.tainted_calls.iter().filter(|c| c.name == "sink").collect();
    // The async-body sink remains visible because Tree-sitter owns the body
    // relationship. No scheduler name is required by the compiler pipeline.
    assert!(
        sink_taints
            .iter()
            .any(|c| c.tainted_args.iter().any(|a| a.value_text == "tainted")),
        "async-body sink(tainted) should appear as a tainted_call; got {sink_taints:?}"
    );
    // Merely observing a tainted argument does not taint an unrelated value
    // in the caller's continuation.
    assert!(
        !sink_taints
            .iter()
            .any(|c| c.tainted_args.iter().any(|a| a.value_text == "also_clean")),
        "post-call sink(also_clean) must remain clean; got {sink_taints:?}"
    );
}
