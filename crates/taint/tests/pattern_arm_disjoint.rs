//! P2.3: Pattern-arm disjointness for Scala. Each match arm runs in
//! its own forked state so taint that arm A creates does not leak
//! into arm B's body. Verified by a fixture where one arm calls a
//! sink with a tainted local variable that is only created in that
//! arm; the other arm should not show up as a tainted-call site.

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

fn tainted_call_to(result: &bonsai_taint::InterTaintResult, name: &str) -> bool {
    result
        .tainted_calls
        .iter()
        .any(|c| c.name == name && !c.tainted_args.is_empty())
}

#[test]
fn swift_switch_arm_disjoint_clean_arm_stays_clean() {
    let src = r#"
func entry(tainted: String, x: Int) {
    switch x {
    case 0:
        let tainted_a = tainted
        sink(tainted_a)
    default:
        let clean_b = "ok"
        sink(clean_b)
    }
}
"#;
    let db = ws(
        Arc::new(bonsai_lang_swift::SwiftAdapter::new()),
        &[("m.swift", src)],
    );
    let entry = func(&db, "entry");
    let result = interprocedural_taint(entry, &seed(&["tainted"]), &config(), &db);
    let sink_taints: Vec<_> = result.tainted_calls.iter().filter(|c| c.name == "sink").collect();
    assert!(
        tainted_call_to(&result, "sink"),
        "tainted_a leg must reach sink in Swift switch"
    );
    let clean_b_tainted = sink_taints
        .iter()
        .any(|c| c.tainted_args.iter().any(|a| a.value_text.contains("clean_b")));
    assert!(
        !clean_b_tainted,
        "Swift default arm clean_b must NOT inherit taint; got {sink_taints:?}"
    );
}

#[test]
fn scala_match_arm_disjoint_clean_arm_stays_clean() {
    // arm A binds `tainted_a` from `tainted` (the entry param).
    // arm B binds `clean_b` from a literal — even though both arms
    // appear in the match, the `clean(clean_b)` call should NOT see
    // `tainted_a` because the engine forks state per arm.
    let src = r#"
object M {
  def entry(tainted: String, x: Int): Unit = x match {
    case 0 =>
      val tainted_a = tainted
      sink(tainted_a)
    case _ =>
      val clean_b = "ok"
      sink(clean_b)
  }
}
"#;
    let db = ws(
        Arc::new(bonsai_lang_scala::ScalaAdapter::new()),
        &[("M.scala", src)],
    );
    let entry = func(&db, "entry");
    let result = interprocedural_taint(entry, &seed(&["tainted"]), &config(), &db);
    // `sink` is called in both arms. With arm-disjoint precision,
    // exactly ONE tainted_call to `sink` should appear (the first
    // arm's, with `tainted_a`). With over-approximation, the second
    // arm's `sink(clean_b)` would also be flagged.
    let sink_taints: Vec<_> = result.tainted_calls.iter().filter(|c| c.name == "sink").collect();
    eprintln!(
        "sink tainted calls: {} args={:?}",
        sink_taints.len(),
        sink_taints
            .iter()
            .map(|c| c.tainted_args.clone())
            .collect::<Vec<_>>()
    );
    assert!(tainted_call_to(&result, "sink"), "tainted_a leg must reach sink");
    let clean_b_tainted = sink_taints
        .iter()
        .any(|c| c.tainted_args.iter().any(|a| a.value_text.contains("clean_b")));
    assert!(
        !clean_b_tainted,
        "clean_b arm must NOT inherit taint from sibling arm; got {sink_taints:?}"
    );
}
