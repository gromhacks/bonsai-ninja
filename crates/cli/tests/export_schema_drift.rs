//! Drift guard for the `bonsai-ninja export --format json` schema.
//!
//! `docs/contributing/specification.mdx`: every `FuncId` referenced in `taint_graph.{call_edges,
//! chains, reachable_facts, assign_chains, intra_taint,
//! function_summaries, flow_id_labels}` must resolve to an entry in
//! `taint_graph.functions[]`. A dangling FuncId means the export's
//! own functions table is incomplete relative to the references it
//! cites — silent JSON divergence that downstream consumers can't
//! recover from.
//!
//! This test runs `bonsai-ninja export --format json` on every
//! language's `micro` fixture and asserts schema completeness. If a
//! future refactor partially rebuilds the functions table without
//! updating one of the reference sections, this fails before any
//! consumer test does.

use serde_json::Value;
use std::collections::BTreeSet;
use std::path::PathBuf;
use std::process::Command;

const LANGS: &[&str] = &[
    "c",
    "cpp",
    "csharp",
    "dart",
    "elixir",
    "erlang",
    "go",
    "java",
    "javascript",
    "kotlin",
    "lua",
    "objc",
    "perl",
    "php",
    "python",
    "ruby",
    "rust",
    "scala",
    "solidity",
    "swift",
    "typescript",
];

fn repo_root() -> PathBuf {
    let mut p = std::env::current_dir().expect("cwd");
    p.push("../..");
    p.canonicalize().expect("repo root")
}

fn bin_path() -> Option<PathBuf> {
    let p = repo_root().join("target/release/bonsai-ninja");
    p.exists().then_some(p)
}

fn run_export(lang: &str) -> Option<Value> {
    let bin = bin_path()?;
    let ws = repo_root().join("examples").join(lang).join("micro");
    if !ws.exists() {
        return None;
    }
    let out = Command::new(&bin)
        .args([
            "export",
            ws.to_str().unwrap(),
            "--format",
            "json",
            "--no-color",
            "--no-progress",
        ])
        .current_dir(repo_root())
        .output()
        .expect("spawn bonsai-ninja");
    assert!(
        out.status.success(),
        "[{lang}] export exit={:?}\nstderr: {}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).expect("export stdout is utf-8");
    let parsed: Value =
        serde_json::from_str(&stdout).unwrap_or_else(|e| panic!("[{lang}] export JSON parse: {e}"));
    Some(parsed)
}

fn collect_func_id_set(taint_graph: &Value) -> BTreeSet<u64> {
    taint_graph
        .get("functions")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(|f| f.get("func_id").and_then(Value::as_u64))
                .collect()
        })
        .unwrap_or_default()
}

fn collect_referenced_func_ids(taint_graph: &Value) -> Vec<(&'static str, u64)> {
    let mut refs: Vec<(&'static str, u64)> = Vec::new();
    let push = |refs: &mut Vec<(&'static str, u64)>, label: &'static str, v: &Value| {
        if let Some(n) = v.as_u64() {
            refs.push((label, n));
        }
    };

    if let Some(arr) = taint_graph.get("call_edges").and_then(Value::as_array) {
        for e in arr {
            if let Some(v) = e.get("from") {
                push(&mut refs, "call_edges.from", v);
            }
            if let Some(v) = e.get("to") {
                push(&mut refs, "call_edges.to", v);
            }
        }
    }
    if let Some(arr) = taint_graph.get("chains").and_then(Value::as_array) {
        for c in arr {
            if let Some(v) = c.get("target_func_id") {
                push(&mut refs, "chains.target_func_id", v);
            }
            if let Some(chains) = c.get("chains").and_then(Value::as_array) {
                for chain in chains {
                    if let Some(hops) = chain.as_array() {
                        for hop in hops {
                            push(&mut refs, "chains.chains[]", hop);
                        }
                    }
                }
            }
        }
    }
    for (section, label) in [
        ("reachable_facts", "reachable_facts.func_id"),
        ("assign_chains", "assign_chains.func_id"),
        ("intra_taint", "intra_taint.func_id"),
        ("flow_id_labels", "flow_id_labels.func_id"),
    ] {
        if let Some(arr) = taint_graph.get(section).and_then(Value::as_array) {
            for entry in arr {
                if let Some(v) = entry.get("func_id") {
                    push(&mut refs, label, v);
                }
            }
        }
    }
    // Note: `function_summaries[].returns_taint_of` is a list of
    // PARAMETER INDICES (which params flow into the return), not
    // FuncIds — deliberately excluded from this reference walk.
    refs
}

fn assert_func_refs_resolve(lang: &str, export: &Value) {
    let Some(taint_graph) = export.get("taint_graph") else {
        panic!("[{lang}] export missing taint_graph");
    };
    let known = collect_func_id_set(taint_graph);
    let refs = collect_referenced_func_ids(taint_graph);
    let mut dangling: Vec<String> = Vec::new();
    for (label, func_id) in &refs {
        if !known.contains(func_id) {
            dangling.push(format!("{label} cites func_id={func_id} not in functions[]"));
        }
    }
    assert!(
        dangling.is_empty(),
        "[{lang}] export taint_graph has dangling FuncId references:\n  {}\n\
         (functions[] count = {}, total references checked = {})",
        dangling.join("\n  "),
        known.len(),
        refs.len()
    );
}

#[test]
fn every_lang_micro_export_funcid_refs_resolve() {
    let Some(_) = bin_path() else {
        eprintln!("skipping export schema drift test: release binary missing");
        return;
    };
    for lang in LANGS {
        let Some(export) = run_export(lang) else {
            continue;
        };
        assert_func_refs_resolve(lang, &export);
    }
}
