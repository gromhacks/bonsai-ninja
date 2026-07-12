use super::{aggregate_flow_precision, dump_taint, TaintFilters, TaintOutcome};
use bonsai_common::Precision;
use bonsai_workspace::Workspace;

#[test]
fn aggregate_flow_precision_keeps_worst_semantic_precision() {
    assert_eq!(
        aggregate_flow_precision([Precision::Exact, Precision::Narrowed, Precision::Exact]),
        Precision::Narrowed
    );
    assert_eq!(aggregate_flow_precision([]), Precision::Exact);
}

#[test]
fn dump_taint_legacy_seed_policy_preserves_clean_overwrite() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(
        dir.path().join("app.py"),
        "def entry(cmd):\n    cmd = 'clean'\n    helper(cmd)\n\ndef helper(value):\n    sink(value)\n",
    )
    .expect("write fixture");
    let ws = Workspace::index(dir.path(), bonsai_adapters::all_languages_registry()).expect("index fixture");

    let outcome = dump_taint(
        &ws,
        &TaintFilters {
            source: "entry",
            seeds: vec!["cmd".to_string()],
            ..Default::default()
        },
    );
    let TaintOutcome::Report(report) = outcome else {
        panic!("dump-taint should resolve entry")
    };
    assert!(
        report.records.is_empty(),
        "canonical parameter seeding must not resurrect the post-seed clean write: {:#?}",
        report.records
    );
}

#[test]
fn dump_taint_legacy_seed_policy_supports_source_call_names() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(
        dir.path().join("app.py"),
        "def entry():\n    raw = source()\n    helper(raw)\n\ndef helper(value):\n    sink(value)\n",
    )
    .expect("write fixture");
    let ws = Workspace::index(dir.path(), bonsai_adapters::all_languages_registry()).expect("index fixture");

    let outcome = dump_taint(
        &ws,
        &TaintFilters {
            source: "entry",
            seeds: vec!["source".to_string()],
            ..Default::default()
        },
    );
    let TaintOutcome::Report(report) = outcome else {
        panic!("dump-taint should resolve entry")
    };
    assert!(
        report.records.iter().any(|record| record.callee_name == "helper"),
        "canonical call-name seed must start at the source call return: {:#?}",
        report.records
    );
}
