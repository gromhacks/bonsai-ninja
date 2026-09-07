//! Security filters select complete canonical units without changing cached analysis.

use serde_json::Value;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::SystemTime;

const SOURCE: &str = r#"import html
import os
from flask import request

def execute(command):
    # audit_dependency_flow_only
    return os.system(command)  # audit_sink_code

def endpoint():
    command = request.args.get("command", "")  # audit_source_code
    # audit_body_only_marker
    return execute(command)

def escaped():
    name = request.args.get("name", "")
    return html.escape(name)  # audit_sanitizer_code
"#;

const ACTIONS: &[&str] = &[
    "sources",
    "sinks",
    "sanitizers",
    "deps",
    "taint-analysis",
    "source-analysis",
    "sink-analysis",
    "dependency-analysis",
];

fn fixture(source: &str) -> tempfile::TempDir {
    let root = tempfile::tempdir().expect("temporary fixture");
    fs::create_dir(root.path().join("workspace")).expect("workspace directory");
    fs::write(root.path().join("workspace/app.py"), source).expect("fixture source");
    root
}

fn run(root: &Path, cache: &Path, action: &str, format: &str, args: &[&str]) -> String {
    let rules = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../security-patterns");
    let mut command = Command::new(env!("CARGO_BIN_EXE_bonsai-ninja"));
    command
        .arg("security")
        .arg(root.join("workspace"))
        .arg(action)
        .arg("--rules-dir")
        .arg(rules)
        .args(["--format", format, "--no-color", "--no-progress"])
        .env("BONSAI_WORKSPACE_DIR", cache)
        .env("COLUMNS", "200")
        .env_remove("BONSAI_CONTEXT")
        .env_remove("BONSAI_NO_CACHE");
    if matches!(action, "taint-analysis" | "source-analysis" | "sink-analysis") {
        command.args(["--profile", "all"]);
    }
    if !args.contains(&"--limit") && !args.contains(&"--context") {
        command.arg("--all");
    }
    let output = command.args(args).output().expect("security command");
    assert!(
        output.status.success(),
        "{action} {format} {args:?}:\n{}\n{}",
        String::from_utf8_lossy(&output.stderr),
        String::from_utf8_lossy(&output.stdout),
    );
    String::from_utf8(output.stdout).expect("UTF-8 security output")
}

fn json(root: &Path, cache: &Path, action: &str, args: &[&str]) -> Value {
    let output = run(root, cache, action, "json", args);
    let value: Value = serde_json::from_str(&output).expect("canonical security JSON");
    assert_eq!(value["analysis_complete"], true, "{value:#}");
    value
}

fn rows(value: &Value) -> &[Value] {
    value["rows"].as_array().expect("security rows")
}

/// Keyed analysis payloads must not be republished just because a view changes.
/// Avoid depending on the page-cache directory's versioned spelling.
fn payload_snapshot(cache: &Path) -> BTreeMap<PathBuf, SystemTime> {
    let mut snapshot = BTreeMap::new();
    let mut pending = vec![cache.to_path_buf()];
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(directory).expect("cache directory") {
            let entry = entry.expect("cache entry");
            let path = entry.path();
            if entry.file_type().expect("cache file type").is_dir() {
                pending.push(path);
            } else if entry.file_name().to_string_lossy().starts_with("payload.")
                && path.extension().is_some_and(|extension| extension == "json")
            {
                snapshot.insert(
                    path,
                    entry.metadata().expect("payload metadata").modified().unwrap(),
                );
            }
        }
    }
    assert!(
        !snapshot.is_empty(),
        "the initial command must warm an analysis payload"
    );
    snapshot
}

#[test]
fn security_file_filter_lists_do_not_collide_in_cached_reports() {
    let root = fixture(SOURCE);
    for action in ACTIONS {
        let expected = json(
            root.path(),
            &root.path().join("uncached"),
            action,
            &["--no-cache"],
        );
        assert!(
            !rows(&expected).is_empty(),
            "{action} fixture must produce evidence"
        );
        for flag in ["--file", "--exclude-file"] {
            let separate = [flag, ".py", flag, ".rs"];
            let joined = [flag, ".py,.rs"];
            for reverse in [false, true] {
                let cache = root.path().join(format!("cache-{action}-{flag}-{reverse}"));
                let requests = if reverse {
                    [separate.as_slice(), joined.as_slice()]
                } else {
                    [joined.as_slice(), separate.as_slice()]
                };
                for args in requests {
                    let actual = json(root.path(), &cache, action, args);
                    let selects_source = (args.len() == 4) == (flag == "--file");
                    let expected_rows = if selects_source { rows(&expected) } else { &[] };
                    assert_eq!(
                        rows(&actual),
                        expected_rows,
                        "{action} {args:?}, reverse={reverse}: distinct lists must not share a payload",
                    );
                    assert_eq!(actual["result_complete"], true, "{actual:#}");
                }
            }
        }
    }
}

#[test]
fn security_render_cursors_include_file_scope_and_secondary_filters() {
    let root = fixture(SOURCE);
    fs::write(root.path().join("workspace/other.py"), SOURCE).expect("second source file");
    for action in ACTIONS {
        let cache = root.path().join(format!("cursor-{action}"));
        let first = json(root.path(), &cache, action, &["--file", "app.py"]);
        let second = json(root.path(), &cache, action, &["--file", "other.py"]);
        assert!(!rows(&first).is_empty() && !rows(&second).is_empty());
        assert_ne!(
            first["page"]["cursor"], second["page"]["cursor"],
            "{action}: different file scopes need different cursors",
        );
        let secondary = json(
            root.path(),
            &cache,
            action,
            &["--file", "app.py", "--not-contains", "audit_absent_needle"],
        );
        assert_eq!(rows(&first), rows(&secondary));
        assert_ne!(
            first["page"]["cursor"], secondary["page"]["cursor"],
            "{action}: secondary selectors belong in the render identity",
        );
    }
}

#[test]
fn security_sanitizer_inventory_honors_severity_category_and_intersection() {
    let root = fixture(SOURCE);
    let cache = root.path().join("cache");
    let base = json(root.path(), &cache, "sanitizers", &[]);
    assert_eq!(rows(&base).len(), 1, "{base:#}");
    assert_eq!(rows(&base)[0]["rule_id"], "python.sanitizer.html_escape");
    let positive = json(
        root.path(),
        &cache,
        "sanitizers",
        &[
            "--category",
            "html-encode",
            "--rule",
            "python.sanitizer.html_escape",
        ],
    );
    assert_eq!(rows(&positive), rows(&base));
    let before = payload_snapshot(&cache);
    for args in [
        vec!["--severity", "critical"],
        vec!["--category", "audit_no_such_category"],
        vec!["--category", "html-encode", "--severity", "info"],
    ] {
        let filtered = json(root.path(), &cache, "sanitizers", &args);
        assert!(rows(&filtered).is_empty(), "{args:?}: {filtered:#}");
        let text = run(root.path(), &cache, "sanitizers", "text", &args);
        assert!(text.contains("0 match(es)"), "{text}");
    }
    assert_eq!(
        payload_snapshot(&cache),
        before,
        "inventory views must reuse the complete inventory"
    );
    let uncached = json(
        root.path(),
        &cache,
        "sanitizers",
        &[
            "--severity",
            "critical",
            "--category",
            "html-encode",
            "--no-cache",
        ],
    );
    assert!(rows(&uncached).is_empty());
}

#[test]
fn security_inventory_secondary_filters_match_hydrated_code_before_paging() {
    let root = fixture(SOURCE);
    let cache = root.path().join("cache");
    for (action, needle) in [
        ("sources", "audit_source_code"),
        ("sinks", "audit_sink_code"),
        ("sanitizers", "audit_sanitizer_code"),
    ] {
        let base = json(root.path(), &cache, action, &[]);
        let expected: Vec<_> = rows(&base)
            .iter()
            .filter(|row| row["code"].as_str().unwrap().contains(needle))
            .cloned()
            .collect();
        assert_eq!(expected.len(), 1, "{action} must have one code-only marker");
        let before = payload_snapshot(&cache);
        let upper = needle.to_uppercase();
        let args = ["--contains", upper.as_str(), "--limit", "1"];
        let selected = json(root.path(), &cache, action, &args);
        assert_eq!(rows(&selected), expected);
        assert_eq!(selected["page"]["total_rows"], 1);
        assert_eq!(selected["page"]["is_last"], true);
        let text = run(root.path(), &cache, action, "text", &args);
        assert!(text.contains(needle), "{text}");
        let dropped = json(root.path(), &cache, action, &["--not-contains", needle]);
        assert_eq!(rows(&dropped).len() + 1, rows(&base).len());
        assert!(rows(&dropped).iter().all(|row| !expected.contains(row)));
        let contradictory = json(
            root.path(),
            &cache,
            action,
            &["--contains", needle, "--not-contains", needle],
        );
        assert!(rows(&contradictory).is_empty());
        assert_eq!(
            payload_snapshot(&cache),
            before,
            "{action} filters must reuse analysis"
        );
    }
}

#[test]
fn security_taint_summary_secondary_filters_match_full_json_text_and_sarif() {
    let root = fixture(SOURCE);
    let cache = root.path().join("cache");
    // Start cold with the summary: body evidence must be available even when
    // no full report has hydrated this analysis yet.
    let cold = json(
        root.path(),
        &cache,
        "taint-analysis",
        &["--summary", "--contains", "audit_body_only_marker"],
    );
    assert_eq!(cold["total_findings"], 1, "{cold:#}");
    let base = json(root.path(), &cache, "taint-analysis", &[]);
    assert_eq!(rows(&base).len(), 1, "{base:#}");
    let description = rows(&base)[0]["presentation"]["rules"]["python.cmdi.os_system"]["description"]
        .as_str()
        .expect("sink description");
    let before = payload_snapshot(&cache);
    for (args, count) in [
        (vec!["--contains", "audit_body_only_marker"], 1),
        (vec!["--not-contains", "audit_body_only_marker"], 0),
        (vec!["--contains", description], 1),
        (vec!["--not-contains", description], 0),
        (
            vec![
                "--contains",
                "audit_body_only_marker",
                "--contains",
                "execute(command)",
            ],
            1,
        ),
    ] {
        let full = json(root.path(), &cache, "taint-analysis", &args);
        assert_eq!(rows(&full).len(), count, "{args:?}: {full:#}");
        let mut summary_args = args.clone();
        summary_args.push("--summary");
        let summary = json(root.path(), &cache, "taint-analysis", &summary_args);
        assert_eq!(summary["total_findings"], count, "{summary:#}");
        let text = run(root.path(), &cache, "taint-analysis", "text", &summary_args);
        assert!(text.contains(&format!("summary — {count} finding(s)")), "{text}");
        let full_text = run(root.path(), &cache, "taint-analysis", "text", &args);
        let id = rows(&base)[0]["finding_id"].as_str().unwrap();
        assert_eq!(full_text.contains(id), count != 0, "{full_text}");
        let sarif: Value = serde_json::from_str(&run(root.path(), &cache, "taint-analysis", "sarif", &args))
            .expect("SARIF JSON");
        assert_eq!(sarif["runs"][0]["results"].as_array().unwrap().len(), count);
    }
    assert_eq!(
        payload_snapshot(&cache),
        before,
        "view changes must not rerun taint analysis"
    );
    let uncached = json(
        root.path(),
        &cache,
        "taint-analysis",
        &["--summary", "--contains", "audit_body_only_marker", "--no-cache"],
    );
    assert_eq!(uncached["total_findings"], 1);
}

#[test]
fn security_sarif_body_filters_match_json_on_cold_and_uncached_paths() {
    let root = fixture(SOURCE);
    let needle = "audit_body_only_marker";
    for (flag, count) in [("--contains", 1), ("--not-contains", 0)] {
        let cache = root.path().join(format!("sarif-first-{count}"));
        for no_cache in [false, true] {
            let mut args = vec![flag, needle];
            if no_cache {
                args.push("--no-cache");
            }
            // SARIF is the first request against this cache. The other parity
            // test covers compact cached rows first warmed by JSON summary.
            let sarif: Value =
                serde_json::from_str(&run(root.path(), &cache, "taint-analysis", "sarif", &args))
                    .expect("SARIF JSON");
            let results = sarif["runs"][0]["results"].as_array().unwrap();
            assert_eq!(results.len(), count, "{args:?}: {sarif:#}");
            let full = json(root.path(), &cache, "taint-analysis", &args);
            assert_eq!(rows(&full).len(), count, "{args:?}: {full:#}");
            for (result, row) in results.iter().zip(rows(&full)) {
                assert_eq!(result["properties"]["bonsai"]["finding_id"], row["finding_id"]);
                assert!(row["flow"]["functions"].to_string().contains(needle));
            }
        }
    }
}

#[test]
fn security_dependency_secondary_filters_match_attached_findings() {
    let root = fixture(SOURCE);
    let cache = root.path().join("cache");
    let base = json(
        root.path(),
        &cache,
        "dependency-analysis",
        &["--framework", "flask"],
    );
    assert_eq!(rows(&base).len(), 1, "{base:#}");
    let needle = "audit_dependency_flow_only";
    assert!(rows(&base)[0]["findings"].to_string().contains(needle));
    assert!(!rows(&base)[0]["sites"].to_string().contains(needle));
    let before = payload_snapshot(&cache);
    let selected = json(
        root.path(),
        &cache,
        "dependency-analysis",
        &["--framework", "flask", "--contains", needle],
    );
    assert_eq!(rows(&selected), rows(&base));
    for field in ["dependency_count", "site_count", "taint_flow_count"] {
        assert_eq!(selected["summary"][field], base["summary"][field]);
        assert_eq!(
            selected["summary"][format!("filtered_{field}")],
            base["summary"][field]
        );
    }
    let text = run(
        root.path(),
        &cache,
        "dependency-analysis",
        "text",
        &["--framework", "flask", "--contains", needle],
    );
    assert!(text.contains(needle), "{text}");
    let excluded = json(
        root.path(),
        &cache,
        "dependency-analysis",
        &["--framework", "flask", "--not-contains", needle],
    );
    assert!(rows(&excluded).is_empty());
    assert_eq!(excluded["page"]["total_rows"], 0);
    for field in ["dependency_count", "site_count", "taint_flow_count"] {
        assert_eq!(excluded["summary"][field], base["summary"][field]);
        assert_eq!(excluded["summary"][format!("filtered_{field}")], 0);
    }
    let excluded_text = run(
        root.path(),
        &cache,
        "dependency-analysis",
        "text",
        &["--framework", "flask", "--not-contains", needle],
    );
    assert!(
        excluded_text.contains("0 selected / 1 total package(s)"),
        "{excluded_text}"
    );
    assert_eq!(
        payload_snapshot(&cache),
        before,
        "dependency views must reuse inventory and taint payloads"
    );
}

#[test]
fn security_sarif_preserves_selected_member_ids_and_combined_evidence() {
    let root = fixture(
        r#"import os
from flask import request

def endpoint():
    first = request.form["first"]
    second = request.form["second"]
    return os.system(first + second)
"#,
    );
    let cache = root.path().join("cache");
    let base = json(root.path(), &cache, "taint-analysis", &[]);
    let combined = rows(&base)
        .iter()
        .find(|row| {
            row["member_finding_ids"]
                .as_array()
                .is_some_and(|ids| ids.len() > 1)
        })
        .expect("two co-tainted sources must retain their member IDs");
    let member = combined["member_finding_ids"]
        .as_array()
        .unwrap()
        .iter()
        .find(|id| **id != combined["finding_id"])
        .and_then(Value::as_str)
        .expect("nonrepresentative member ID");
    assert!(!combined["additional_sources"].as_array().unwrap().is_empty());
    let selected = json(root.path(), &cache, "taint-analysis", &["--finding", member]);
    assert_eq!(rows(&selected), std::slice::from_ref(combined));
    for extra in [vec![], vec!["--no-cache"]] {
        let mut args = vec!["--finding", member];
        args.extend(extra);
        let sarif: Value = serde_json::from_str(&run(root.path(), &cache, "taint-analysis", "sarif", &args))
            .expect("SARIF JSON");
        let results = sarif["runs"][0]["results"].as_array().unwrap();
        assert_eq!(
            results.len(),
            1,
            "member drilldown must retain one combined finding"
        );
        let metadata = &results[0]["properties"]["bonsai"];
        assert_eq!(metadata["finding_id"], combined["finding_id"]);
        assert_eq!(metadata["member_finding_ids"], combined["member_finding_ids"]);
        assert_eq!(metadata["additional_sources"], combined["additional_sources"]);
        assert_eq!(
            metadata["additional_sinks"],
            combined
                .get("additional_sinks")
                .cloned()
                .unwrap_or_else(|| serde_json::json!([]))
        );
        assert_eq!(metadata["flow_id"], combined["representative_flow_id"]);
        assert_eq!(metadata["source_rule_id"], combined["source"]["rule_id"]);
        assert_eq!(metadata["sink_rule_id"], combined["sink"]["rule_id"]);
        assert_eq!(metadata["status"], combined["status"]);
    }
}
