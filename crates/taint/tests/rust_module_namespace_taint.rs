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
    InterTaintConfig::default()
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

#[test]
fn grouped_crate_member_type_dispatches_to_macro_wrapped_enum_impl() {
    let handle_rs = r#"
use crate::runtime::{context, scheduler};

pub struct Handle {
    inner: scheduler::Handle,
}

impl Handle {
    pub(crate) fn spawn(&self, future: String) {}

    pub(crate) fn spawn_named(&self, future: String) {
        self.inner.spawn(future);
    }
}
"#;
    let scheduler_rs = r#"
macro_rules! cfg_rt { ($($item:item)*) => { $($item)* } }

cfg_rt! {
    pub(crate) enum Handle {
        Current,
        Multi,
    }

    impl Handle {
        pub(crate) fn spawn(&self, future: String) {}
    }
}
"#;
    let db = ws(
        Arc::new(bonsai_lang_rust::RustAdapter::new()),
        &[
            ("tokio/src/runtime/handle.rs", handle_rs),
            ("tokio/src/runtime/scheduler/mod.rs", scheduler_rs),
        ],
    );
    let global = db.global_index();
    let caller = FuncId::new(
        global
            .find_by_name("spawn_named")
            .first()
            .copied()
            .expect("spawn_named")
            .raw(),
    );
    let scheduler_file = db
        .vfs()
        .all_files()
        .into_iter()
        .find(|file| {
            db.vfs()
                .path(*file)
                .is_ok_and(|path| path.ends_with("tokio/src/runtime/scheduler/mod.rs"))
        })
        .expect("scheduler file");
    let scheduler_spawn = global
        .find_by_name("spawn")
        .iter()
        .copied()
        .find(|symbol| global.declaring_file(*symbol) == Some(scheduler_file))
        .map(|symbol| FuncId::new(symbol.raw()))
        .expect("scheduler Handle::spawn");
    let caller_decl = global
        .decl_of(bonsai_common::SymbolId::new(caller.raw()))
        .expect("spawn_named decl");
    let caller_file = global
        .declaring_file(caller_decl.symbol)
        .expect("spawn_named file");
    let alias_targets = bonsai_lang_api::alias_map_from_import_specs(&db.imports_for_uncached(caller_file))
        .into_iter()
        .collect::<ahash::AHashMap<_, _>>();
    let path_lookup = |file| {
        db.vfs()
            .path(file)
            .ok()
            .map(|path| path.to_string_lossy().into_owned())
    };
    let resolve_context = bonsai_resolve::ResolveContext::new(caller_file, &caller_decl.module_path)
        .with_alias_map(&alias_targets)
        .with_file_path_lookup(&path_lookup)
        .with_module_path_syntax(bonsai_lang_api::ModulePathSyntax {
            rooted_prefixes: &["crate::", "self::"],
            repeatable_rooted_prefixes: &["super::"],
        });
    let resolved_types = bonsai_resolve::resolve_class(&global, "scheduler.Handle", &resolve_context);
    assert_eq!(
        resolved_types,
        vec![global
            .decl_of(bonsai_common::SymbolId::new(scheduler_spawn.raw()))
            .and_then(|method| method.parent)
            .expect("scheduler Handle")],
        "rooted grouped member type resolution must select scheduler.Handle; aliases={alias_targets:?}"
    );
    let headers = db.build_global_header_index();
    let header_caller = headers
        .find_by_name("spawn_named")
        .first()
        .copied()
        .expect("spawn_named header");
    let header_caller_decl = headers.decl_of(header_caller).expect("spawn_named header decl");
    let header_context = bonsai_resolve::ResolveContext::new(caller_file, &header_caller_decl.module_path)
        .with_alias_map(&alias_targets)
        .with_file_path_lookup(&path_lookup)
        .with_module_path_syntax(bonsai_lang_api::ModulePathSyntax {
            rooted_prefixes: &["crate::", "self::"],
            repeatable_rooted_prefixes: &["super::"],
        });
    let header_types = bonsai_resolve::resolve_class(&headers, "scheduler.Handle", &header_context);
    assert_eq!(
        header_types.iter().map(|symbol| symbol.raw()).collect::<Vec<_>>(),
        resolved_types
            .iter()
            .map(|symbol| symbol.raw())
            .collect::<Vec<_>>(),
        "streaming headers must preserve type resolution"
    );
    let remapped_caller = db
        .decl_index_remapped_to_headers(&headers, caller_file)
        .expect("remapped caller body")
        .defs
        .into_iter()
        .find(|decl| decl.name == "spawn_named")
        .expect("remapped spawn_named body");
    assert_eq!(
        remapped_caller.type_aliases, caller_decl.type_aliases,
        "streaming body remap must preserve receiver types"
    );
    let receiver_types = remapped_caller
        .flow_events
        .iter()
        .find_map(|event| match event {
            bonsai_lang_api::FlowEvent::Call {
                name, receiver_types, ..
            } if name == "self.inner.spawn" => Some(receiver_types.as_slice()),
            _ => None,
        })
        .expect("self.inner.spawn call fact");
    assert_eq!(receiver_types, ["scheduler.Handle"]);
    let targets = bonsai_taint::build_resolved_call_graph_snapshot(&db)
        .callees_of(caller)
        .map(|edge| edge.to)
        .collect::<Vec<_>>();

    assert_eq!(targets, vec![scheduler_spawn]);
}
