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
    if let Some(path) = option_env!("CARGO_BIN_EXE_bonsai-ninja") {
        return Some(PathBuf::from(path));
    }
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

fn assert_top_level_callgraph_is_semantic(lang: &str, export: &Value) {
    let rows = export
        .get("callgraph")
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("[{lang}] export missing callgraph"));
    for row in rows {
        let precision = row
            .get("precision")
            .and_then(Value::as_str)
            .unwrap_or("<missing>");
        assert!(
            matches!(precision, "exact" | "narrowed"),
            "[{lang}] export.callgraph must be semantic-only; got precision={precision} row={row}"
        );
        assert_provenance_fields(lang, "export.callgraph", row);
    }
    let summary_count = export
        .get("summary")
        .and_then(|s| s.get("call_edge_count"))
        .and_then(Value::as_u64)
        .unwrap_or(u64::MAX);
    assert_eq!(
        summary_count,
        rows.len() as u64,
        "[{lang}] summary.call_edge_count must match semantic callgraph rows"
    );
}

fn assert_taint_call_edges_have_provenance(lang: &str, export: &Value) {
    let rows = export
        .get("taint_graph")
        .and_then(|tg| tg.get("call_edges"))
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("[{lang}] export missing taint_graph.call_edges"));
    for row in rows {
        assert_provenance_fields(lang, "taint_graph.call_edges", row);
    }
}

fn assert_provenance_fields(lang: &str, section: &'static str, row: &Value) {
    let stage = row.get("resolver_stage").and_then(Value::as_str).unwrap_or("");
    let evidence = row.get("evidence").and_then(Value::as_str).unwrap_or("");
    let confidence = row.get("confidence").and_then(Value::as_u64);
    assert!(
        !stage.is_empty() && !evidence.is_empty() && confidence.is_some_and(|value| value <= 100),
        "[{lang}] {section} row missing resolver provenance: {row}"
    );
}

fn assert_flow_graph_names_are_workspace_functions(lang: &str, export: &Value) {
    let Some(taint_graph) = export.get("taint_graph") else {
        panic!("[{lang}] export missing taint_graph");
    };
    let known_names: BTreeSet<String> = taint_graph
        .get("functions")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|f| f.get("name").and_then(Value::as_str).map(str::to_string))
        .collect();
    let rows = export
        .get("flow_graph")
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("[{lang}] export missing flow_graph"));
    for row in rows {
        for field in ["callers", "outgoing"] {
            if let Some(names) = row.get(field).and_then(Value::as_array) {
                for name in names {
                    let Some(name) = name.as_str() else {
                        panic!("[{lang}] flow_graph.{field} contains non-string value: {name}");
                    };
                    assert!(
                        known_names.contains(name),
                        "[{lang}] flow_graph.{field} contains non-workspace function `{name}` in row {row}"
                    );
                }
            }
        }
    }
}

fn assert_python_export_preserves_decl_extent_and_import_symbols(export: &Value) {
    let files = export
        .get("files")
        .and_then(Value::as_array)
        .expect("export files array");
    let gateway = files
        .iter()
        .find(|file| {
            file.get("path")
                .and_then(Value::as_str)
                .is_some_and(|path| path.ends_with("gateway.py"))
        })
        .expect("gateway.py export file");
    let handle_request = gateway
        .get("decls")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .find(|decl| decl.get("name").and_then(Value::as_str) == Some("handle_request"))
        .expect("handle_request decl");
    assert_eq!(
        handle_request.get("line").and_then(Value::as_u64),
        Some(10),
        "handle_request start line drifted: {handle_request}"
    );
    assert_eq!(
        handle_request.get("end_line").and_then(Value::as_u64),
        Some(17),
        "export decl end_line must cover the full function body: {handle_request}"
    );

    let imported_names: BTreeSet<String> = gateway
        .get("imports")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|imp| imp.get("module").and_then(Value::as_str) == Some(".user_service"))
        .filter_map(|imp| {
            imp.get("original_name")
                .and_then(Value::as_str)
                .map(str::to_string)
        })
        .collect();
    assert_eq!(
        imported_names,
        BTreeSet::from(["get_user".to_string(), "update_user".to_string()]),
        "export imports must preserve per-symbol original_name facts: {gateway}"
    );
}

fn collect_export_import_rows(export: &Value) -> Vec<&Value> {
    export
        .get("files")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .flat_map(|file| {
            file.get("imports")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
        })
        .collect()
}

fn assert_lua_export_hides_module_table_bindings(export: &Value) {
    let rows = collect_export_import_rows(export);
    assert!(
        !rows
            .iter()
            .any(|row| row.get("alias").and_then(Value::as_str) == Some("M")),
        "Lua export must not expose resolver-only module table alias M as an import row: {rows:?}"
    );
    for (module, alias) in [
        ("luasql.sqlite3", "luasql"),
        ("auth_service", "auth"),
        ("user_service", "user_service"),
    ] {
        assert!(
            rows.iter().any(|row| {
                row.get("module").and_then(Value::as_str) == Some(module)
                    && row.get("alias").and_then(Value::as_str) == Some(alias)
            }),
            "Lua export missing real require row module={module} alias={alias}: {rows:?}"
        );
    }
}

fn assert_ruby_export_hides_inferred_constant_bindings(export: &Value) {
    let rows = collect_export_import_rows(export);
    assert!(
        rows.iter()
            .all(|row| row.get("alias").and_then(Value::as_str).is_none()),
        "Ruby export must not expose inferred constants as standalone import aliases: {rows:?}"
    );
    for module in ["auth_service", "sinatra", "sqlite3", "user_service"] {
        assert!(
            rows.iter()
                .any(|row| row.get("module").and_then(Value::as_str) == Some(module)),
            "Ruby export missing real require row module={module}: {rows:?}"
        );
    }
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
        assert_top_level_callgraph_is_semantic(lang, &export);
        assert_taint_call_edges_have_provenance(lang, &export);
        assert_flow_graph_names_are_workspace_functions(lang, &export);
    }
}

#[test]
fn python_export_preserves_decl_extent_and_import_symbols() {
    let Some(_) = bin_path() else {
        eprintln!("skipping export schema drift test: release binary missing");
        return;
    };
    let export = run_export("python").expect("python export");
    assert_python_export_preserves_decl_extent_and_import_symbols(&export);
}

#[test]
fn export_hides_resolver_only_import_bindings() {
    let Some(_) = bin_path() else {
        eprintln!("skipping export schema drift test: release binary missing");
        return;
    };
    let lua = run_export("lua").expect("lua export");
    assert_lua_export_hides_module_table_bindings(&lua);
    let ruby = run_export("ruby").expect("ruby export");
    assert_ruby_export_hides_inferred_constant_bindings(&ruby);
}
