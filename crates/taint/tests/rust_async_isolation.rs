//! P3.1: Rust async/await — adapter wraps detached-future bodies
//! (`tokio::spawn`, `std::thread::spawn`, etc.) in Defer so taint
//! flowing into the spawned body does not propagate to the caller's
//! continuation. Taint inside the spawn body is still observed at
//! sink calls inside the spawn (so security findings still fire);
//! it just doesn't bleed forward into post-spawn statements.

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
    InterTaintConfig {
        budget: 512,
        ..Default::default()
    }
}

fn seed(names: &[&str]) -> TokenSet {
    names.iter().map(|n| (*n).to_string()).collect()
}

#[test]
fn tokio_spawn_body_taint_is_observed_inside_but_not_post_spawn() {
    let src = r#"
async fn entry(tainted: String, also_clean: String) {
    tokio::spawn(async move {
        sink(tainted);
    });
    sink(also_clean);
}
"#;
    let db = ws(Arc::new(bonsai_lang_rust::RustAdapter::new()), &[("m.rs", src)]);
    let entry = func(&db, "entry");
    let result = interprocedural_taint(entry, &seed(&["tainted"]), &config(), &db);
    let sink_taints: Vec<_> = result.tainted_calls.iter().filter(|c| c.name == "sink").collect();
    // The spawn-body sink(tainted) IS observable as a tainted_call
    // (the engine walks Defer body events) — so finding-style rules
    // still fire on dangerous spawned futures.
    assert!(
        sink_taints
            .iter()
            .any(|c| c.tainted_args.iter().any(|a| a.value_text == "tainted")),
        "spawn-body sink(tainted) should still appear as a tainted_call; got {sink_taints:?}"
    );
    // The post-spawn sink(also_clean) must NOT be tainted — the
    // spawn body's taint was isolated by Defer so it doesn't bleed
    // into the caller's continuation state.
    assert!(
        !sink_taints
            .iter()
            .any(|c| c.tainted_args.iter().any(|a| a.value_text == "also_clean")),
        "post-spawn sink(also_clean) must NOT inherit taint from the spawn body; got {sink_taints:?}"
    );
}
