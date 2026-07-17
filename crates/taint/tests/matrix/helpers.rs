//! Shared helpers for the taint test matrix.
//!
//! - `LangFixture` describes one language's shape of a scenario.
//! - `run_positive_cell` / `run_negative_cell` execute the engine and
//!   assert the matrix cell's expected outcome.
//! - `adapter_for(lang)` constructs the right `AdapterArc` for a
//!   language id (mirrors `bonsai_adapters` but is decoupled so the
//!   matrix runs without the registry façade).

#![allow(dead_code, unreachable_pub)]

use crate::applicability::{status, Status};
use bonsai_common::FuncId;
use bonsai_db::AnalyzerDb;
use bonsai_lang_api::{AdapterArc, LanguageRegistry};
use bonsai_taint::{interprocedural_taint, InterTaintConfig, TaintedCallKind, TokenSet};
use bonsai_vfs::Vfs;
use std::sync::Arc;

pub struct LangFixture {
    pub lang: &'static str,
    pub adapter: AdapterArc,
    pub files: &'static [(&'static str, &'static str)],
    pub entry: &'static str,
    pub seed: &'static [&'static str],
    pub sink: &'static str,
}

pub fn build_db(adapter: AdapterArc, files: &[(&str, &str)]) -> AnalyzerDb {
    let vfs = Arc::new(Vfs::new());
    for (path, source) in files {
        vfs.write((*path).to_string(), Arc::<str>::from(*source));
    }
    let registry = Arc::new(LanguageRegistry::new());
    registry.register(adapter);
    let db = AnalyzerDb::new(vfs, registry);
    for file in db.vfs().all_files() {
        let _ = db.decl_index(file);
    }
    db
}

pub fn func_id_or_none(db: &AnalyzerDb, name: &str) -> Option<FuncId> {
    let candidates = bonsai_resolve::resolve_callable(&db.global_index(), name);
    candidates.into_iter().next()
}

pub fn seed(names: &[&str]) -> TokenSet {
    names.iter().map(|n| (*n).to_string()).collect()
}

pub fn cfg() -> InterTaintConfig {
    InterTaintConfig::default()
}

fn sink_name_matches(actual: &str, sink: &str) -> bool {
    actual == sink
        || actual.ends_with(&format!(".{sink}"))
        || actual.ends_with(&format!("::{sink}"))
        || actual.ends_with(&format!(":{sink}"))
}

pub fn sink_reached(result: &bonsai_taint::InterTaintResult, sink: &str) -> bool {
    result
        .tainted_calls
        .iter()
        .any(|c| sink_name_matches(&c.name, sink))
}

pub fn sink_received_arg_text(result: &bonsai_taint::InterTaintResult, sink: &str, text: &str) -> bool {
    result
        .tainted_calls
        .iter()
        .any(|c| sink_name_matches(&c.name, sink) && c.tainted_args.iter().any(|a| a.value_text == text))
}

pub fn sink_received_arg_index(result: &bonsai_taint::InterTaintResult, sink: &str, index: usize) -> bool {
    result.tainted_calls.iter().any(|c| {
        sink_name_matches(&c.name, sink)
            && c.kind == TaintedCallKind::Call
            && c.tainted_args.iter().any(|arg| arg.index == index)
    })
}

/// Run a positive matrix cell: the sink MUST receive taint via the
/// declared seed. Skips automatically when the cell is `NotApplicable`
/// or `AdapterDeferred`.
pub fn run_positive_cell(scenario_id: &str, fixture: LangFixture) {
    if matches!(
        status(fixture.lang, scenario_id),
        Status::NotApplicable | Status::AdapterDeferred
    ) {
        return;
    }
    let db = build_db(fixture.adapter, fixture.files);
    let entry = func_id_or_none(&db, fixture.entry).unwrap_or_else(|| {
        panic!(
            "[{}/{}] entry `{}` should index",
            scenario_id, fixture.lang, fixture.entry
        )
    });
    let result = interprocedural_taint(entry, &seed(fixture.seed), &cfg(), &db);
    assert!(
        sink_reached(&result, fixture.sink),
        "[{}/{}] sink `{}` MUST receive taint from seed {:?}; got {:?}",
        scenario_id,
        fixture.lang,
        fixture.sink,
        fixture.seed,
        result.tainted_calls,
    );
}

/// Run a negative matrix cell: the sink MUST NOT receive taint via
/// the declared seed. Most over-taint scenarios use this. Skips
/// automatically when the cell is `NotApplicable` / `AdapterDeferred`.
pub fn run_negative_cell(scenario_id: &str, fixture: LangFixture) {
    if matches!(
        status(fixture.lang, scenario_id),
        Status::NotApplicable | Status::AdapterDeferred
    ) {
        return;
    }
    let db = build_db(fixture.adapter, fixture.files);
    let entry = func_id_or_none(&db, fixture.entry).unwrap_or_else(|| {
        panic!(
            "[{}/{}] entry `{}` should index",
            scenario_id, fixture.lang, fixture.entry
        )
    });
    let result = interprocedural_taint(entry, &seed(fixture.seed), &cfg(), &db);
    assert!(
        !sink_reached(&result, fixture.sink),
        "[{}/{}] sink `{}` MUST stay clean for seed {:?}; got {:?}",
        scenario_id,
        fixture.lang,
        fixture.sink,
        fixture.seed,
        result.tainted_calls,
    );
}
