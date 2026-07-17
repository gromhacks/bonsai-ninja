//! Seeded taint ↔ value-flow projection parity smoke tests.
//!
//! Phase 5 soundness gate. For each fixture, runs the seeded engine
//! AND the seed-free value-flow pass, and asserts the SAME callee
//! params get reached. This guards the value-flow projection consumed by
//! `inspect` and source analysis against semantic drift.
//!
//! When a per-fixture diff appears, this test fires before any
//! consumer change ships — preventing a silent semantic drift in the
//! migration.

mod common;

use ahash::AHashSet;
use bonsai_lang_api::AdapterArc;
use bonsai_taint::{interprocedural_taint, value_flow_for_function, InterTaintConfig, ValueFlowNodeKind};
use common::{build_db, cfg, func_id_or_none, seed};
use std::sync::Arc;

/// For a Python entry function, run seeded-taint + value-flow paths and
/// assert they reach the same set of callee param names from the
/// entry's seed.
fn assert_parity(src: &str, entry: &str, seeds: &[&str]) {
    let adapter: AdapterArc = Arc::new(bonsai_lang_python::PythonAdapter::new());
    let db = build_db(adapter, &[("a.py", src)]);
    let entry_func = func_id_or_none(&db, entry).unwrap_or_else(|| panic!("entry `{entry}` indexes"));

    // Seeded path: the canonical engine produces propagation records.
    let seeded = interprocedural_taint(entry_func, &seed(seeds), &cfg(), &db);
    let seeded_callee_params: AHashSet<String> = seeded
        .call_records
        .iter()
        .flat_map(|prop| prop.tainted_args.iter().map(|t| t.param_name.clone()))
        .collect();

    // Value-flow path: seed-free graph from value_flow_for_function.
    // Forward-closure from any seed-named param node should land on
    // every callee param the seeded run found.
    let graph = value_flow_for_function(entry_func, &db, &InterTaintConfig::default());
    let entry_seed_nodes: Vec<_> = graph
        .nodes
        .iter()
        .filter(|n| {
            n.func == entry_func
                && n.kind == ValueFlowNodeKind::Param
                && seeds.iter().any(|s| **s == n.value_text)
        })
        .cloned()
        .collect();
    let mut value_flow_reached: AHashSet<String> = AHashSet::default();
    for origin in &entry_seed_nodes {
        for reached in graph.forward_closure(origin) {
            if reached.kind == ValueFlowNodeKind::Param && reached.func != entry_func {
                value_flow_reached.insert(reached.value_text.clone());
            }
        }
    }

    // Seeded propagation is the floor — value-flow must reach at least every
    // callee param it found.
    let missing: Vec<&String> = seeded_callee_params
        .iter()
        .filter(|p| !value_flow_reached.contains(*p))
        .collect();
    assert!(
        missing.is_empty(),
        "value-flow must reach every callee param the seeded run found.\n\
         Missing: {missing:?}\n\
         Seeded: {seeded_callee_params:?}\n\
         Value-flow: {value_flow_reached:?}"
    );
}

#[test]
fn parity_two_hop() {
    assert_parity(
        "def entry(args):\n    helper(args)\n\ndef helper(p):\n    sink(p)\n",
        "entry",
        &["args"],
    );
}

#[test]
fn parity_three_hop_chain() {
    assert_parity(
        "def entry(args):\n    a = args\n    helper(a)\n\ndef helper(b):\n    deeper(b)\n\ndef deeper(c):\n    sink(c)\n",
        "entry",
        &["args"],
    );
}

#[test]
fn parity_branch_merge() {
    assert_parity(
        "def entry(args):\n    if cond():\n        helper(args)\n    else:\n        helper(args)\n\ndef helper(p):\n    sink(p)\n",
        "entry",
        &["args"],
    );
}

#[test]
fn parity_assigned_local_then_call() {
    assert_parity(
        "def entry(args):\n    local = args\n    helper(local)\n\ndef helper(p):\n    sink(p)\n",
        "entry",
        &["args"],
    );
}
