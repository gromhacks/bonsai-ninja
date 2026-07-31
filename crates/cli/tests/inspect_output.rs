//! Integration tests for the CLI's `inspect` command output shape.
//!
//! These invoke the compiled binary and assert on the text it produces so
//! that the terminology ("MATCH" not "SINK") and downstream-expansion
//! behavior don't regress.

use std::path::PathBuf;
use std::process::Command;

fn ws_path() -> PathBuf {
    // Tests run with the crate dir as CWD; the repo-root examples live two
    // levels up.
    let mut p = std::env::current_dir().expect("cwd");
    p.push("../../examples/python/micro");
    p.canonicalize().expect("examples/python/micro not found")
}

fn bin_path() -> PathBuf {
    if let Some(path) = option_env!("CARGO_BIN_EXE_bonsai-ninja") {
        return PathBuf::from(path);
    }
    let mut p = std::env::current_dir().expect("cwd");
    p.push("../../target/release/bonsai-ninja");
    p
}

fn require_binary_built() -> Option<PathBuf> {
    let b = bin_path();
    if b.exists() {
        Some(b)
    } else {
        eprintln!(
            "skipping inspect integration test: release binary not built ({})",
            b.display()
        );
        None
    }
}

fn tempdir_for_test(prefix: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let root = std::env::temp_dir();
    for attempt in 0..100 {
        let td = root.join(format!("{prefix}-{}-{nanos:x}-{attempt}", std::process::id()));
        match std::fs::create_dir(&td) {
            Ok(()) => return td,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => panic!("create tempdir {}: {e}", td.display()),
        }
    }
    panic!("could not allocate tempdir for {prefix}");
}

fn run(args: &[&str]) -> String {
    let Some(bin) = require_binary_built() else {
        return String::new();
    };
    let out = Command::new(bin)
        .args(args)
        .arg("--no-color")
        .output()
        .expect("failed to run bonsai-ninja");
    assert!(
        out.status.success(),
        "bonsai-ninja exited with {}: {}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).to_string()
}

fn run_json(args: &[&str]) -> serde_json::Value {
    let out = run(args);
    serde_json::from_str(&out).unwrap_or_else(|err| panic!("valid inspect JSON ({err}):\n{out}"))
}

#[test]
fn inspect_uses_match_not_sink() {
    if require_binary_built().is_none() {
        return;
    }
    let ws = ws_path();
    let out = run(&[
        "inspect",
        ws.to_str().unwrap(),
        "run_admin_command",
        "--graph-flow",
    ]);
    assert!(!out.contains("SINK"), "output still contains SINK: {out}");
    assert!(out.contains("MATCH"), "output missing MATCH annotation: {out}");
}

#[test]
fn inspect_fuzzy_substring_matches_decl() {
    if require_binary_built().is_none() {
        return;
    }
    let ws = ws_path();
    let out = run(&["inspect", ws.to_str().unwrap(), "run_admin"]);
    assert!(
        out.contains("run_admin_command"),
        "expected fuzzy match to surface run_admin_command: {out}"
    );
}

#[test]
fn inspect_request_shows_downstream_chain() {
    if require_binary_built().is_none() {
        return;
    }
    let ws = ws_path();
    let out = run(&["inspect", ws.to_str().unwrap(), "request", "--graph-flow"]);
    // The request match lives in handle_request, which is the root. Its
    // downstream should reach run_admin_command and os.system transitively.
    assert!(
        out.contains("run_admin_command"),
        "expected downstream to include run_admin_command: {out}"
    );
    assert!(
        out.contains("os.system"),
        "expected downstream to include os.system: {out}"
    );
}

#[test]
fn inspect_qualified_call_name_preserved() {
    if require_binary_built().is_none() {
        return;
    }
    let ws = ws_path();
    let out = run(&["inspect", ws.to_str().unwrap(), "os.system", "--graph-flow"]);
    assert!(out.contains("os.system"), "qualified call name missing: {out}");
    // Should have a flow from root -> update_user -> run_admin_command.
    assert!(
        out.contains("run_admin_command"),
        "flow chain missing in output: {out}"
    );
}

#[test]
fn inspect_owner_qualified_declaration_name_matches() {
    if require_binary_built().is_none() {
        return;
    }
    let root = tempdir_for_test("inspect-qualified-decl");
    std::fs::write(
        root.join("RestSearchAction.java"),
        r#"
package org.elasticsearch.rest;
class RestSearchAction {
    void prepareRequest(String request) {
        Runnable deferred = () -> helper(request);
    }
    void helper(String request) {}
}
"#,
    )
    .expect("write Java qualified-name fixture");

    let out = run(&[
        "inspect",
        root.to_str().unwrap(),
        "RestSearchAction.prepareRequest",
        "--format",
        "json",
        "--no-progress",
    ]);
    let report: serde_json::Value = serde_json::from_str(&out).expect("qualified inspect JSON");
    assert!(
        report["decl_hits"]
            .as_array()
            .is_some_and(|hits| { hits.len() == 1 && hits[0]["symbol"] == "prepareRequest" }),
        "owner-qualified inspect query must match the compiler-qualified declaration: {out}"
    );
}

#[test]
fn exact_file_graph_flow_does_not_expand_to_a_cold_workspace_graph() {
    if require_binary_built().is_none() {
        return;
    }
    let root = tempdir_for_test("inspect-cold-file-graph");
    std::fs::write(
        root.join("entry.py"),
        "def entry(value):\n    return target(value)\n\ndef target(value):\n    return value\n",
    )
    .expect("write selected source");
    std::fs::write(
        root.join("unrelated.py"),
        "def unrelated(value):\n    return value\n",
    )
    .expect("write unrelated source");

    let out = run(&[
        "inspect",
        root.to_str().unwrap(),
        "target",
        "--file",
        "entry.py",
        "--graph-flow",
        "--format",
        "json",
        "--no-progress",
    ]);
    let report: serde_json::Value = serde_json::from_str(&out).expect("cold graph inspect JSON");
    assert_eq!(report["summary"]["total_decl_hits"], 1);
    assert_eq!(report["analysis_complete"], false);
    assert!(
        report["analysis_incomplete_reasons"]
            .as_array()
            .is_some_and(|reasons| reasons.iter().any(|reason| reason
                .as_str()
                .is_some_and(|reason| reason.contains("reverse-call index is not warmed")))),
        "cold exact-file graph query must disclose unavailable upstream coverage: {out}"
    );
}

#[test]
fn inspect_json_no_matches_keeps_report_shape() {
    if require_binary_built().is_none() {
        return;
    }
    let ws = ws_path();
    let out = run(&[
        "inspect",
        ws.to_str().unwrap(),
        "--query",
        "definitely_not_in_fixture_9f13e0",
        "--format",
        "json",
        "--no-progress",
    ]);
    let v: serde_json::Value = serde_json::from_str(&out).expect("valid inspect JSON");
    assert!(v.is_object(), "inspect JSON no-match must be an object: {out}");
    assert_eq!(v["decl_hits"].as_array().map(Vec::len), Some(0));
    assert_eq!(v["hits"].as_array().map(Vec::len), Some(0));
    assert_eq!(v["taint_flows"].as_array().map(Vec::len), Some(0));
    assert!(
        v["summary"].is_object(),
        "inspect JSON no-match must keep summary field: {out}"
    );
}

#[test]
fn inspect_filter_only_to_does_not_promote_unrelated_function_facts_to_matches() {
    if require_binary_built().is_none() {
        return;
    }
    let td = tempdir_for_test("inspect-to-filter-precision");
    std::fs::write(
        td.join("app.py"),
        r#"import os
import pickle

def restore_session(data):
    """VULN: Insecure deserialization"""
    default_dir = os.environ.get("MODEL_DIR", "/var/models")
    restored = pickle.loads(data)
    return restored

def load_from_pickle(data):
    """VULN: Insecure deserialization"""
    model = pickle.loads(data)
    return model
"#,
    )
    .expect("write fixture");

    let out = run(&[
        "inspect",
        td.to_str().unwrap(),
        "--to",
        "pickle",
        "--graph-flow",
        "--taint-flow",
        "--all",
        "--format",
        "json",
        "--no-progress",
    ]);
    let v: serde_json::Value = serde_json::from_str(&out).expect("valid inspect JSON");
    let hits = v["hits"].as_array().expect("hits array");

    assert!(!hits.is_empty(), "expected pickle occurrence hits: {out}");
    assert!(
        hits.iter().all(|hit| {
            let kind = hit["kind"].as_str().unwrap_or_default();
            let text = hit["text"].as_str().unwrap_or_default();
            matches!(kind, "call" | "var") && text.contains("pickle")
        }),
        "filter-only --to pickle should only promote direct pickle facts, got:\n{out}"
    );

    let rendered_annotations: Vec<String> = hits
        .iter()
        .flat_map(|hit| hit["flows"].as_array().into_iter().flatten())
        .flat_map(|flow| flow["functions"].as_array().into_iter().flatten())
        .flat_map(|function| function["lines"].as_array().into_iter().flatten())
        .filter_map(|line| line["annotation"].as_str())
        .map(str::to_string)
        .collect();

    assert!(
        rendered_annotations.iter().all(|annotation| {
            annotation.contains("pickle")
                && !annotation.contains("VULN")
                && !annotation.contains("MODEL_DIR")
                && !annotation.contains("/var/models")
        }),
        "filter markers must stay on pickle evidence, got annotations:\n{rendered_annotations:#?}"
    );

    let mut labels_by_flow = std::collections::BTreeMap::<String, std::collections::BTreeSet<String>>::new();
    let mut numbers_by_flow = std::collections::BTreeMap::<String, std::collections::BTreeSet<u64>>::new();
    for flow in hits
        .iter()
        .flat_map(|hit| hit["flows"].as_array().into_iter().flatten())
    {
        let flow_id = flow["flow_id"].as_str().unwrap_or_default().to_string();
        labels_by_flow
            .entry(flow_id.clone())
            .or_default()
            .insert(flow["flow_label"].as_str().unwrap_or_default().to_string());
        numbers_by_flow
            .entry(flow_id)
            .or_default()
            .insert(flow["flow_number"].as_u64().unwrap_or_default());
    }
    assert!(
        labels_by_flow.values().all(|labels| labels.len() == 1),
        "the same F: flow must not render with multiple labels:\n{labels_by_flow:#?}\n{out}"
    );
    assert!(
        numbers_by_flow.values().all(|numbers| numbers.len() == 1),
        "the same F: flow must not render with multiple flow_number values:\n{numbers_by_flow:#?}\n{out}"
    );

    let text_out = run(&[
        "inspect",
        td.to_str().unwrap(),
        "--to",
        "pickle",
        "--graph-flow",
        "--all",
        "--no-progress",
    ]);
    let annotated_pickle_lines: Vec<&str> = text_out
        .lines()
        .filter(|line| line.contains("pickle.loads(data)  # [FLOW"))
        .collect();
    assert!(
        !annotated_pickle_lines.is_empty()
            && annotated_pickle_lines
                .iter()
                .all(|line| line.contains("MATCH: call pickle.loads")),
        "folded FLOW bodies should annotate the direct call fact, not the assignment wrapper:\n{annotated_pickle_lines:#?}\n{text_out}"
    );

    let taint_flows = v["taint_flows"].as_array().expect("taint flows array");
    assert!(
        taint_flows
            .iter()
            .flat_map(|flow| flow["steps"].as_array().into_iter().flatten())
            .all(|step| {
                step["tainted_args"].as_array().into_iter().flatten().all(|arg| {
                    !(arg["param_name"].as_str() == Some("receiver")
                        && arg["value_text"].as_str() == Some("pickle"))
                })
            }),
        "module/callee target components must not be reported as tainted receivers:\n{out}"
    );
    assert!(
        taint_flows
            .iter()
            .flat_map(|flow| flow["steps"].as_array().into_iter().flatten())
            .filter(|step| {
                step["kind"].as_str() == Some("call")
                    && step["callee"].as_str().is_some_and(|callee| callee.starts_with("pickle."))
            })
            .all(|step| step["column"].as_u64().is_some_and(|column| column > 5)),
        "assignment-RHS raw taint terminal calls must point at the call token, not the assignment start:\n{out}"
    );

    let call_only = run(&[
        "inspect",
        td.to_str().unwrap(),
        "--to",
        "pickle",
        "--to-kind",
        "call",
        "--all",
        "--format",
        "json",
        "--no-progress",
    ]);
    let call_only_v: serde_json::Value = serde_json::from_str(&call_only).expect("valid inspect JSON");
    let call_only_hits = call_only_v["hits"].as_array().expect("hits array");
    assert!(
        !call_only_hits.is_empty()
            && call_only_hits
                .iter()
                .all(|hit| hit["kind"].as_str() == Some("call")),
        "--to-kind call must not promote var/string facts as call endpoints:\n{call_only}"
    );
    let mut seen_call_locations = std::collections::BTreeSet::new();
    for hit in call_only_hits {
        let key = (
            hit["text"].as_str().unwrap_or_default(),
            hit["file"].as_str().unwrap_or_default(),
            hit["line"].as_u64().unwrap_or_default(),
            hit["column"].as_u64().unwrap_or_default(),
        );
        assert!(
            seen_call_locations.insert(key),
            "--to-kind call must not duplicate the same call hit location:\n{call_only}"
        );
    }

    let _ = std::fs::remove_dir_all(td);
}

#[test]
fn inspect_syntax_fast_path_respects_endpoint_kind_filters() {
    if require_binary_built().is_none() {
        return;
    }
    let td = tempdir_for_test("inspect-syntax-endpoint-kind");
    std::fs::write(
        td.join("app.py"),
        r#"import pickle

def load(data):
    model = pickle.loads(data)
    return model
"#,
    )
    .expect("write fixture");

    let out = run(&[
        "inspect",
        td.to_str().unwrap(),
        "--query",
        "pickle",
        "--to",
        "pickle",
        "--to-kind",
        "call",
        "--format",
        "json",
        "--no-progress",
    ]);
    let v: serde_json::Value = serde_json::from_str(&out).expect("valid inspect JSON");
    let hits = v["hits"].as_array().expect("hits array");
    assert!(!hits.is_empty(), "expected direct pickle call hit:\n{out}");
    assert!(
        hits.iter().all(|hit| {
            hit["kind"].as_str() == Some("call")
                && hit["text"].as_str().is_some_and(|text| text.contains("pickle"))
        }),
        "syntax fast path must use typed endpoint evidence, not assignment text:\n{out}"
    );

    let _ = std::fs::remove_dir_all(td);
}

#[test]
fn inspect_text_disambiguates_duplicate_chain_hop_names() {
    if require_binary_built().is_none() {
        return;
    }
    let mut ws = std::env::current_dir().expect("cwd");
    ws.push("../../examples/python");
    let ws = ws.canonicalize().expect("examples/python not found");

    let out = run(&[
        "inspect",
        ws.to_str().unwrap(),
        "--to",
        "pickle",
        "--graph-flow",
        "--all",
        "--no-progress",
    ]);
    let bad_chain_lines: Vec<&str> = out
        .lines()
        .map(str::trim)
        .filter(|line| {
            *line == "predict → predict → load_model" || *line == "predict -> predict -> load_model"
        })
        .collect();
    assert!(
        bad_chain_lines.is_empty(),
        "duplicate same-name chain lines should be display-disambiguated:\n{bad_chain_lines:#?}\n{out}"
    );
    assert!(
        out.contains("complex.app.predict → InferenceEngine.predict → load_model")
            || out.contains("complex.app.predict -> InferenceEngine.predict -> load_model"),
        "expected owner/module-qualified display for duplicate predict hops:\n{out}"
    );
}

#[test]
fn inspect_small_workspace_does_not_build_retrieval_sidecar_as_truth_filter() {
    if require_binary_built().is_none() {
        return;
    }
    let td = tempdir_for_test("inspect-no-query-time-retrieval");
    std::fs::write(td.join("a.py"), "def alpha_target():\n    return 1\n").expect("write a");
    std::fs::write(td.join("b.py"), "def beta_target():\n    return 2\n").expect("write b");

    let out = run(&[
        "inspect",
        td.to_str().unwrap(),
        "--query",
        "beta_target",
        "--format",
        "json",
        "--no-progress",
    ]);
    let v: serde_json::Value = serde_json::from_str(&out).expect("valid inspect JSON");
    assert_eq!(
        v["decl_hits"].as_array().map(Vec::len),
        Some(1),
        "inspect should hydrate the canonical decl hit without requiring retrieval:\n{out}"
    );
    assert_eq!(
        v["decl_hits"][0]["symbol"].as_str(),
        Some("beta_target"),
        "unexpected inspect hit:\n{out}"
    );

    let bonsai_dir = td.join(".bonsai");
    if bonsai_dir.exists() {
        let retrieval_sidecars: Vec<_> = std::fs::read_dir(&bonsai_dir)
            .expect("read .bonsai")
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().starts_with("retrieval.v"))
            .collect();
        assert!(
            retrieval_sidecars.is_empty(),
            "inspect should not build retrieval sidecars during small-workspace query-time hydration"
        );
    }

    let _ = std::fs::remove_dir_all(td);
}

#[test]
fn inspect_default_is_lightweight_syntax_evidence() {
    if require_binary_built().is_none() {
        return;
    }
    let ws = ws_path();
    let out = run(&["inspect", ws.to_str().unwrap(), "--query", "os.system"]);
    assert!(
        out.contains("os.system") && !out.contains("══ TAINT FLOWS") && !out.contains("taint flow(s)"),
        "default inspect should return syntax evidence without silently running taint: {out}"
    );
}

#[test]
fn inspect_footer_counts_taint_and_occurrence_only_results() {
    if require_binary_built().is_none() {
        return;
    }
    let ws = ws_path();
    let out = run(&[
        "inspect",
        ws.to_str().unwrap(),
        "--query",
        "os.system",
        "--taint-flow",
        "--context",
        "4k",
    ]);
    assert!(
        out.contains("══ TAINT FLOWS") && out.contains("══ OCCURRENCE HITS"),
        "fixture should render taint and occurrence tables: {out}"
    );
    assert!(
        !out.contains("page 1 of 1 (0 rows)") && out.contains("inspect items"),
        "inspect footer should count visible non-structural rows: {out}"
    );
}

#[test]
fn inspect_explicit_taint_flow_adds_rulepack_free_paths() {
    if require_binary_built().is_none() {
        return;
    }
    let ws = ws_path();
    let out = run(&[
        "inspect",
        ws.to_str().unwrap(),
        "--query",
        "os.system",
        "--taint-flow",
    ]);
    assert!(
        out.contains("os.system"),
        "explicit taint inspect should retain the syntax hit: {out}"
    );
    assert!(
        out.contains("══ TAINT FLOWS") && out.contains("taint flow(s)") && out.contains("T:"),
        "--taint-flow should add raw taint evidence: {out}"
    );
}

#[test]
fn inspect_rejects_removed_syntax_only_switch() {
    let Some(bin) = require_binary_built() else {
        return;
    };
    let ws = ws_path();
    let result = Command::new(bin)
        .args([
            "inspect",
            ws.to_str().unwrap(),
            "--query",
            "os.system",
            "--syntax-only",
            "--no-color",
        ])
        .output()
        .expect("run removed switch check");
    let stderr = String::from_utf8_lossy(&result.stderr);
    assert!(
        !result.status.success() && stderr.contains("unexpected argument '--syntax-only'"),
        "removed redundant switch should fail with clap command truth: {stderr}"
    );
}

#[test]
fn inspect_secondary_contains_filters_taint_rows() {
    if require_binary_built().is_none() {
        return;
    }
    let ws = ws_path();
    let v = run_json(&[
        "inspect",
        ws.to_str().unwrap(),
        "--query",
        "os.system",
        "--taint-flow",
        "--contains",
        "notify-admin",
        "--format",
        "json",
    ]);
    assert_eq!(
        v["taint_flows"].as_array().map(Vec::len),
        Some(1),
        "--contains must keep the taint row whose argument value contains the needle: {v:#}"
    );
    assert_eq!(
        v["hits"].as_array().map(Vec::len),
        Some(0),
        "--contains must not retain an independent syntax row merely because another taint row matches: {v:#}"
    );
}

#[test]
fn inspect_secondary_not_contains_drops_only_matching_taint_rows() {
    if require_binary_built().is_none() {
        return;
    }
    let ws = ws_path();
    let v = run_json(&[
        "inspect",
        ws.to_str().unwrap(),
        "--query",
        "os.system",
        "--taint-flow",
        "--not-contains",
        "notify-admin",
        "--format",
        "json",
    ]);
    // Inspect `--format json` returns the report object; a fully
    // filtered result has every row section empty (decl_hits / hits /
    // taint_flows), which is the drop-all outcome the secondary filter
    // must produce here.
    let section_empty = |key: &str| {
        v.get(key)
            .and_then(|section| section.as_array())
            .is_some_and(Vec::is_empty)
    };
    assert!(
        section_empty("decl_hits")
            && !section_empty("hits")
            && section_empty("taint_flows"),
        "--not-contains must remove the matching taint row without dropping the independent syntax call: {v:#}"
    );
}

#[test]
fn inspect_taint_flow_id_rerenders_without_query() {
    if require_binary_built().is_none() {
        return;
    }
    let ws = ws_path();
    let first = run_json(&[
        "inspect",
        ws.to_str().unwrap(),
        "--query",
        "os.system",
        "--taint-flow",
        "--format",
        "json",
    ]);
    let taint_id = first["taint_flows"]
        .as_array()
        .and_then(|flows| flows.first())
        .and_then(|flow| flow["taint_id"].as_str())
        .expect("initial inspect taint id")
        .to_string();
    let rerender = run_json(&[
        "inspect",
        ws.to_str().unwrap(),
        "--flow",
        &taint_id,
        "--format",
        "json",
    ]);
    let flows = rerender["taint_flows"]
        .as_array()
        .expect("rerendered taint flows");
    assert_eq!(
        flows.len(),
        1,
        "--flow T:... should keep exactly one taint row: {rerender:#}"
    );
    assert_eq!(
        flows[0]["taint_id"].as_str(),
        Some(taint_id.as_str()),
        "--flow T:... should match taint_id exactly: {rerender:#}"
    );
    assert!(
        rerender["decl_hits"].as_array().is_none_or(Vec::is_empty)
            && rerender["hits"].as_array().is_none_or(Vec::is_empty),
        "--flow T:... should not leak unrelated structural rows: {rerender:#}"
    );
}

#[test]
fn inspect_from_to_filters_include_structural_flows_by_default() {
    if require_binary_built().is_none() {
        return;
    }
    let ws = ws_path();
    let out = run(&[
        "inspect",
        ws.to_str().unwrap(),
        "--from",
        "run_admin_command",
        "--to",
        "os.system",
    ]);
    assert!(
        out.contains("FLOW ") && out.contains("run_admin_command") && out.contains("os.system"),
        "filter-only inspect should include structural paths that satisfy --from/--to: {out}"
    );
}

#[test]
fn inspect_regex_flag_works() {
    if require_binary_built().is_none() {
        return;
    }
    let ws = ws_path();
    let out = run(&["inspect", ws.to_str().unwrap(), "--regex", "^run_admin_.*"]);
    assert!(out.contains("run_admin_command"), "regex match missing: {out}");
}

#[test]
fn inspect_reports_hit_counts_by_kind() {
    if require_binary_built().is_none() {
        return;
    }
    let ws = ws_path();
    let out = run(&["inspect", ws.to_str().unwrap(), "request"]);
    assert!(out.contains("by kind:"), "hit-kind summary missing: {out}");
}

#[test]
fn inspect_accepts_query_flag() {
    if require_binary_built().is_none() {
        return;
    }
    let ws = ws_path();
    let out = run(&["inspect", ws.to_str().unwrap(), "--query", "run_admin"]);
    assert!(
        out.contains("run_admin_command"),
        "--query flag did not resolve fuzzy match: {out}"
    );
}

#[test]
fn inspect_kind_filter_restricts_output() {
    if require_binary_built().is_none() {
        return;
    }
    let ws = ws_path();
    // Filtering to calls-only should not surface the decl match block.
    let out = run(&[
        "inspect",
        ws.to_str().unwrap(),
        "--kind",
        "call",
        "run_admin_command",
    ]);
    assert!(
        out.contains("by kind:") && out.contains("call: 1"),
        "missing call-kind summary: {out}"
    );
    assert!(
        !out.contains("== run_admin_command (function)"),
        "decl block should not appear under --kind call: {out}"
    );
}

#[test]
fn inspect_call_hit_surfaces_full_upstream_chain() {
    // Regression: on a qualified call hit (`authService.runAdminCommand`
    // inside UserService.updateUser), the flow for the SINK call
    // `Runtime.getRuntime().exec` should trace all the way up to the
    // entry point `handleRequest`, not collapse to just the containing
    // function. This reproduces the Kotlin-micro regression where cross-
    // class method calls short-circuited the caller-map lookup.
    if require_binary_built().is_none() {
        return;
    }
    let repo_root: std::path::PathBuf = {
        let mut p = std::env::current_dir().expect("cwd");
        p.push("../..");
        p.canonicalize().expect("repo root")
    };
    let ws = repo_root.join("examples/kotlin/micro");
    let out = run(&["inspect", ws.to_str().unwrap(), "--query", "exec", "--graph-flow"]);
    assert!(
        out.contains("handleRequest → updateUser → runAdminCommand"),
        "expected full cross-class chain for exec hit, got:\n{out}"
    );
    // The exec flow is not necessarily FLOW 1 (the `executeQuery` SQLi
    // flows substring-match `exec` and group ahead of it); assert the
    // source annotation traces to the entry point regardless of the
    // flow's group label.
    assert!(
        out.contains("SOURCE: entry handleRequest"),
        "expected SOURCE annotation at handleRequest, got:\n{out}"
    );
}

#[test]
fn inspect_call_hit_does_not_expand_unresolved_qualified_call_to_sibling_short_name() {
    if require_binary_built().is_none() {
        return;
    }
    let td = tempdir_for_test("inspect-semantic-call-hit");
    std::fs::write(
        td.join("app.py"),
        r#"def caller():
    helper("safe")
    external.helper("user")

def helper(value):
    return value
"#,
    )
    .expect("write fixture");

    let out = run(&[
        "inspect",
        td.to_str().unwrap(),
        "--query",
        "external.helper",
        "--kind",
        "call",
        "--graph-flow",
        "--format",
        "json",
        "--no-progress",
    ]);
    let v: serde_json::Value = serde_json::from_str(&out).expect("valid inspect JSON");
    let hit = v["hits"]
        .as_array()
        .and_then(|hits| hits.first())
        .expect("call hit");
    let chains: Vec<Vec<String>> = hit["flows"]
        .as_array()
        .expect("flows array")
        .iter()
        .map(|flow| {
            flow["chain"]
                .as_array()
                .expect("chain array")
                .iter()
                .map(|name| name.as_str().expect("chain entry").to_string())
                .collect()
        })
        .collect();
    assert_eq!(
        chains,
        vec![vec!["caller".to_string()]],
        "unresolved external.helper() must not bind to the sibling helper() call:\n{out}"
    );
}

#[test]
fn inspect_flow_bodies_show_class_owner_context() {
    if require_binary_built().is_none() {
        return;
    }
    let Some(bin) = require_binary_built() else {
        return;
    };
    let td = tempdir_for_test("bonsai_owner_context_test");
    let src = "class Gateway {\n\
  void handle(String cmd) { sink(cmd); }\n\
  void sink(String cmd) { Runtime.getRuntime().exec(cmd); }\n\
}\n";
    std::fs::write(td.join("Gateway.java"), src).unwrap();
    let out = Command::new(bin)
        .args([
            "inspect",
            td.to_str().unwrap(),
            "--query",
            "exec",
            "--graph-flow",
            "--no-color",
        ])
        .output()
        .expect("run bonsai-ninja");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("[class] Gateway"),
        "flow render dropped class owner context:\n{stdout}"
    );
    assert!(
        stdout.contains("[def] handle(cmd)") || stdout.contains("[def] sink(cmd)"),
        "flow render dropped function header:\n{stdout}"
    );
    let _ = std::fs::remove_dir_all(&td);
}

#[test]
fn inspect_flow_labels_use_letter_suffix_on_branch_split() {
    // A sink reached via two sibling paths should render as FLOW Na / Nb,
    // not two separate numeric flows.
    if require_binary_built().is_none() {
        return;
    }
    let Some(bin) = require_binary_built() else {
        return;
    };
    let td = tempdir_for_test("bonsai_flow_label_test");
    let src = "import os\n\
def sink(cmd):\n    os.system(cmd)\n\
def left(cmd):\n    sink(cmd)\n\
def right(cmd):\n    sink(cmd)\n\
def handle_request(cmd, path):\n    if path == '/l':\n        left(cmd)\n    else:\n        right(cmd)\n";
    std::fs::write(td.join("a.py"), src).unwrap();
    let out = Command::new(bin)
        .args([
            "inspect",
            td.to_str().unwrap(),
            "sink",
            "--graph-flow",
            "--no-color",
        ])
        .output()
        .expect("run bonsai-ninja");
    let stdout = String::from_utf8_lossy(&out.stdout);
    // At least one label should include a letter suffix (e.g. 1a / 1b).
    let has_letter_label = stdout
        .lines()
        .any(|l| l.contains("FLOW 1a") || l.contains("FLOW 2a"));
    assert!(
        has_letter_label,
        "expected letter-suffix flow label for sibling chain, got:\n{stdout}"
    );
    let _ = std::fs::remove_dir_all(&td);
}
