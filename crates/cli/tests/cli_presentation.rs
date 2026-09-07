//! Human-readable views preserve canonical facts while adapting their layout.

use std::path::PathBuf;
use std::process::Command;

fn workspace() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/python/language_gauntlet")
        .canonicalize()
        .expect("Python example")
}

fn run(command: &str, options: &[&str], cache: &std::path::Path, width: &str) -> String {
    let output = Command::new(env!("CARGO_BIN_EXE_bonsai-ninja"))
        .arg(command)
        .arg(workspace())
        .args(options)
        .args(["--no-color", "--no-progress"])
        .env("BONSAI_WORKSPACE_DIR", cache)
        .env("COLUMNS", width)
        .env_remove("BONSAI_CONTEXT")
        .env_remove("BONSAI_NO_CACHE")
        .output()
        .expect("run CLI");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("UTF-8 output")
}

#[test]
fn every_browse_command_has_a_heading_and_cross_module_section() {
    let cache = tempfile::tempdir().expect("cache");
    for (command, options) in [
        ("defs", vec![]),
        ("entrypoints", vec![]),
        ("calls", vec![]),
        ("imports", vec![]),
        ("vars", vec![]),
        ("strings", vec![]),
        ("comments", vec![]),
        ("args", vec![]),
        ("operations", vec![]),
        ("classes", vec![]),
        ("refs", vec!["--symbol", "execute"]),
        ("search", vec!["--query", "execute"]),
    ] {
        let text = run(command, &options, cache.path(), "140");
        assert!(text.starts_with(&format!("{command} — ")), "{command}: {text}");
        assert!(text.contains("used in (cross-module)"), "{command}: {text}");
        assert!(!text.contains("\x1b["));
    }
}

#[test]
fn every_browse_command_preserves_empty_result_and_cross_module_contracts() {
    let cache = tempfile::tempdir().expect("cache");
    for command in [
        "defs",
        "entrypoints",
        "calls",
        "imports",
        "vars",
        "strings",
        "comments",
        "args",
        "operations",
        "classes",
        "refs",
        "search",
    ] {
        let mut options = match command {
            "refs" => vec!["--symbol", "execute"],
            "search" => vec!["--query", "execute"],
            _ => vec![],
        };
        options.extend(["--contains", "zzz_no_such_browse_fact_7329"]);
        let text = run(command, &options, cache.path(), "80");
        assert!(text.starts_with(&format!("{command} — 0 ")), "{command}: {text}");
        assert!(text.contains("used in (cross-module)"), "{command}: {text}");
        assert!(!text.contains("\x1b["), "{command}: {text}");
        options.extend(["--format", "json"]);
        let json: serde_json::Value =
            serde_json::from_str(&run(command, &options, cache.path(), "80")).expect("JSON");
        assert_eq!(json["rows"], serde_json::json!([]), "{command}: {json}");
        assert_eq!(json["used_in"], serde_json::json!([]), "{command}: {json}");
        assert_eq!(json["result_complete"], true, "{command}: {json}");
        assert_eq!(json["page"]["shown_rows"], 0, "{command}: {json}");
        assert_eq!(json["page"]["is_last"], true, "{command}: {json}");
    }
}

#[test]
fn resized_cached_pages_reflow_and_keep_identical_json_rows() {
    let cache = tempfile::tempdir().expect("cache");
    // Call names render in full; literal/comment names deliberately use
    // previews in both layouts and retain their full value in JSON.
    let options = ["--query", "execute", "--kind", "call", "--all"];
    let mut json_options = options.to_vec();
    json_options.extend(["--format", "json"]);
    let wide = run("search", &options, cache.path(), "180");
    let narrow = run("search", &options, cache.path(), "80");
    assert_ne!(wide, narrow, "resizing must not replay old formatted bytes");
    assert_eq!(narrow, run("search", &options, cache.path(), "80"));
    let normalized_narrow = narrow.split_whitespace().collect::<Vec<_>>().join(" ");
    for width in ["80", "180"] {
        let json: serde_json::Value =
            serde_json::from_str(&run("search", &json_options, cache.path(), width)).expect("JSON");
        assert!(json["page"]["is_last"].as_bool().unwrap());
        let rows = json["rows"].as_array().unwrap();
        assert!(!rows.is_empty());
        for row in rows {
            let name = row["name"].as_str().expect("name");
            let normalized_name = name.split_whitespace().collect::<Vec<_>>().join(" ");
            assert!(
                normalized_narrow.contains(&normalized_name),
                "narrow output lost {name}: {narrow}"
            );
        }
        if width == "80" {
            let wide_json: serde_json::Value =
                serde_json::from_str(&run("search", &json_options, cache.path(), "180")).unwrap();
            assert_eq!(json["rows"], wide_json["rows"]);
        }
    }
}

#[test]
fn finding_route_precedes_rule_prose_and_single_page_footer_is_clear() {
    let cache = tempfile::tempdir().expect("cache");
    let text = run(
        "security",
        &["taint-analysis", "--context", "16k"],
        cache.path(),
        "100",
    );
    assert!(
        text.starts_with("security taint-analysis — 1 finding\n"),
        "{text}"
    );
    assert!(
        text.find("chain:").unwrap() < text.find("cwe:").unwrap(),
        "{text}"
    );
    assert!(
        text.find("source:").unwrap() < text.find("cwe:").unwrap(),
        "{text}"
    );
    assert!(text.find("sink:").unwrap() < text.find("cwe:").unwrap(), "{text}");
    assert!(text.contains("page 1 of 1 (1 finding)"), "{text}");
    assert!(!text.contains("full uncapped:"), "{text}");
}

#[test]
fn corridor_target_matches_are_not_presented_as_proven_endpoints() {
    let cache = tempfile::tempdir().expect("cache");
    let text = run(
        "inspect-graph",
        &[
            "--from",
            "handle_request",
            "--to",
            "os.system",
            "--compact",
            "--all",
        ],
        cache.path(),
        "140",
    );
    assert!(
        text.contains("target call matches (not a reachability claim)"),
        "{text}"
    );
    assert!(
        text.contains("clean_twin"),
        "target evidence must not disappear: {text}"
    );
    assert!(
        !text.contains("backends "),
        "engine diagnostics belong in JSON/debug: {text}"
    );
    assert!(!text.contains("semantic flow:"), "{text}");
}
