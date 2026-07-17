//! Shared test helpers for the over-taint regression matrix.
//!
//! Files in `tests/common/` are not standalone test binaries (Rust
//! convention); they are mod-included from sibling `tests/*.rs`
//! files. Every helper here is `pub` because it crosses the test
//! crate / module boundary.

#![allow(dead_code)]
// `unreachable_pub` doesn't apply to test-binary mod-files: the
// binary has no public API surface, but the helpers still need
// `pub` so sibling test files can call them. Allow the lint here.
#![allow(unreachable_pub)]

use bonsai_common::FuncId;
use bonsai_db::AnalyzerDb;
use bonsai_lang_api::{AdapterArc, LanguageRegistry};
use bonsai_taint::{interprocedural_taint, InterTaintConfig, TaintedCallKind, TokenSet};
use bonsai_vfs::Vfs;
use std::sync::Arc;

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

/// True when there is any tainted_call whose name matches `sink_name`
/// (exact or qualified-tail match) AND whose tainted_args contain
/// the given value text.
pub fn sink_received_arg_text(
    result: &bonsai_taint::InterTaintResult,
    sink_name: &str,
    arg_text: &str,
) -> bool {
    result.tainted_calls.iter().any(|c| {
        let name_match = c.name == sink_name
            || c.name.ends_with(&format!(".{sink_name}"))
            || c.name.ends_with(&format!("::{sink_name}"))
            || c.name.ends_with(&format!(":{sink_name}"));
        name_match && c.tainted_args.iter().any(|a| a.value_text == arg_text)
    })
}

/// True when the sink name is reached by *any* tainted call.
pub fn sink_reached(result: &bonsai_taint::InterTaintResult, sink_name: &str) -> bool {
    result.tainted_calls.iter().any(|c| {
        c.name == sink_name
            || c.name.ends_with(&format!(".{sink_name}"))
            || c.name.ends_with(&format!("::{sink_name}"))
            || c.name.ends_with(&format!(":{sink_name}"))
    })
}

pub fn sink_received_arg_index(
    result: &bonsai_taint::InterTaintResult,
    sink_name: &str,
    index: usize,
) -> bool {
    result.tainted_calls.iter().any(|c| {
        let name_match = c.name == sink_name
            || c.name.ends_with(&format!(".{sink_name}"))
            || c.name.ends_with(&format!("::{sink_name}"))
            || c.name.ends_with(&format!(":{sink_name}"));
        name_match && c.kind == TaintedCallKind::Call && c.tainted_args.iter().any(|arg| arg.index == index)
    })
}

pub fn assert_audit_tainted_but_sink_clean(
    lang: &str,
    adapter: AdapterArc,
    file: &str,
    src: &str,
    entry_name: &str,
    seed_names: &[&str],
    sink_name: &str,
) {
    let db = build_db(adapter, &[(file, src)]);
    let entry = func_id_or_none(&db, entry_name)
        .unwrap_or_else(|| panic!("{lang}: entry `{entry_name}` should index"));
    let result = interprocedural_taint(entry, &seed(seed_names), &cfg(), &db);
    assert!(
        sink_received_arg_index(&result, "audit", 0),
        "{lang}: audit(seed) must be tainted so the negative sink assertion is meaningful; got {:?}",
        result.tainted_calls,
    );
    assert!(
        !sink_reached(&result, sink_name),
        "{lang}: sink `{sink_name}` must stay clean; got {:?}",
        result.tainted_calls,
    );
}
