//! Rust `::` module namespace taint propagation across files.
//!
//! Locks the regression where `use crate::executor;` (or other
//! workspace-internal paths with no `as`-rename and no brace-list)
//! left the local module name unbound in the alias map, so
//! `executor::execute(...)` could not be resolved by the taint
//! engine even though the callgraph already crossed the edge.

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
        let _ = db.import_index(f);
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
fn use_crate_module_namespace_call_propagates_arg_taint() {
    let main_rs = r#"
mod pipeline;

fn entry(raw: String) {
    pipeline::orchestrate(raw);
}
"#;
    let pipeline_rs = r#"
use crate::executor;

pub fn orchestrate(envelope: String) {
    executor::execute(envelope);
}
"#;
    let executor_rs = r#"
pub fn execute(cmd: String) {
    sink(cmd);
}
"#;
    let db = ws(
        Arc::new(bonsai_lang_rust::RustAdapter::new()),
        &[
            ("src/main.rs", main_rs),
            ("src/pipeline.rs", pipeline_rs),
            ("src/executor.rs", executor_rs),
        ],
    );
    let entry = func(&db, "entry");
    let result = interprocedural_taint(entry, &seed(&["raw"]), &config(), &db);

    let sink_taints: Vec<_> = result.tainted_calls.iter().filter(|c| c.name == "sink").collect();
    assert!(
        sink_taints
            .iter()
            .any(|c| c.tainted_args.iter().any(|a| a.value_text == "cmd")),
        "tainted arg must reach sink across `mod pipeline;` and `use crate::executor;` namespaced calls; got {:?}",
        result.tainted_calls
    );

    // Both cross-module call edges must record direct propagations:
    // entry → orchestrate via `pipeline::orchestrate`, and orchestrate
    // → execute via `use crate::executor;` + `executor::execute`.
    let orchestrate = func(&db, "orchestrate");
    let execute = func(&db, "execute");
    assert!(
        result
            .call_records
            .iter()
            .any(|c| c.caller == entry && c.callee == orchestrate),
        "entry → orchestrate edge must be recorded for `pipeline::orchestrate`; got {:?}",
        result.call_records
    );
    assert!(
        result
            .call_records
            .iter()
            .any(|c| c.caller == orchestrate && c.callee == execute),
        "orchestrate → execute edge must be recorded for `use crate::executor;` + `executor::execute`; got {:?}",
        result.call_records
    );
}

#[test]
fn use_crate_type_import_does_not_create_namespace_alias() {
    // `use crate::Envelope;` imports a type, not a module. The
    // adapter must not bind `Envelope` as a workspace namespace
    // alias — doing so would let `Envelope::method` rewrite to a
    // workspace `method` decl via the resolver's bare-name
    // fallback, fabricating an unrelated edge.
    let main_rs = r#"
mod helpers;

#[derive(Clone)]
pub struct Envelope { pub cmd: String }

fn entry(value: String) {
    let envelope = Envelope { cmd: value };
    helpers::handle(envelope);
}
"#;
    let helpers_rs = r#"
use crate::Envelope;

pub fn handle(env: Envelope) {
    sink(env.cmd);
}

pub fn method(token: String) {
    danger(token);
}
"#;
    let db = ws(
        Arc::new(bonsai_lang_rust::RustAdapter::new()),
        &[("src/main.rs", main_rs), ("src/helpers.rs", helpers_rs)],
    );
    let entry = func(&db, "entry");
    let result = interprocedural_taint(entry, &seed(&["value"]), &config(), &db);

    // `helpers::handle` resolves through `mod helpers;`. `Envelope`
    // is a struct import and must NOT introduce an `Envelope ::
    // method` rewrite that would synthesize an entry → method
    // edge.
    let danger_taints: Vec<_> = result
        .tainted_calls
        .iter()
        .filter(|c| c.name == "danger")
        .collect();
    assert!(
        danger_taints.is_empty(),
        "`use crate::Envelope;` (type import) must not bind a workspace namespace alias \
         that lets `Envelope::method` resolve to an unrelated workspace function; got {danger_taints:?}"
    );
}
