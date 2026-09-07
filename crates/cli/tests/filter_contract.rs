//! Filters select facts, independently of flag placement and presentation.

use serde_json::{json, Value};
use std::path::Path;
use std::process::{Command, Output};

fn fixture(root: &Path) {
    std::fs::create_dir_all(root).unwrap();
    std::fs::write(
        root.join("app.py"),
        concat!(
            "import os\n",
            "def alpha(value):\n",
            "    # Alpha Token\n",
            "    label = 'Alpha Token'\n",
            "    return os.system(value)\n",
            "def beta(value):\n",
            "    # Beta Other\n",
            "    label = 'Beta Other'\n",
            "    return str(value)\n",
            "class Holder:\n",
            "    def apply(self, value):\n",
            "        return beta(value)\n",
        ),
    )
    .unwrap();
    std::fs::write(
        root.join("client.py"),
        "from app import alpha\ndef entry(value):\n    # Client note\n    return alpha(value)\n",
    )
    .unwrap();
}

fn run(root: &Path, cache: &Path, prefix: &[&str], command: &[&str], flags: &[&str]) -> Output {
    let mut process = Command::new(env!("CARGO_BIN_EXE_bonsai-ninja"));
    process.args(prefix).arg(command[0]).arg(root).args(&command[1..]);
    process
        .args(flags)
        .args(["--no-color", "--no-progress"])
        .env("BONSAI_WORKSPACE_DIR", cache)
        .env_remove("BONSAI_CONTEXT")
        .env_remove("BONSAI_NO_CACHE")
        .output()
        .unwrap()
}

fn document(output: Output) -> Value {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("canonical JSON")
}

fn leaves(value: &Value, output: &mut Vec<String>) {
    match value {
        Value::String(text) => output.push(text.to_lowercase()),
        Value::Array(values) => values.iter().for_each(|value| leaves(value, output)),
        Value::Object(values) => {
            for (key, value) in values {
                if key != "presentation" {
                    leaves(value, output);
                }
            }
        }
        _ => {}
    }
}

fn matches(row: &Value, needle: &str) -> bool {
    let mut values = Vec::new();
    leaves(row, &mut values);
    values.iter().any(|value| value.contains(&needle.to_lowercase()))
}

fn facts(row: &Value) -> Value {
    let mut row = row.clone();
    row.as_object_mut().unwrap().remove("presentation");
    row
}

#[test]
fn endpoint_flow_reopens_with_rulepack_free_provenance_and_secondary_filters() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("workspace");
    let cache = temp.path().join("cache");
    fixture(&root);
    let report = document(run(
        &root,
        &cache,
        &[],
        &["inspect-graph"],
        &["--from", "entry", "--to", "alpha", "--all", "--format", "json"],
    ));
    let corridor = &report["corridor"];
    let id = corridor["stack"]["flow_id"]
        .as_str()
        .expect("exact corridor flow");
    for _ in 0..2 {
        let reopened = document(run(
            &root,
            &cache,
            &[],
            &["show", "--id", id],
            &["--contains", id, "--compact", "--all", "--format", "json"],
        ));
        for key in ["from", "to", "nodes", "edges"] {
            assert_eq!(reopened["corridor"][key], corridor[key], "{key}");
        }
        assert_eq!(reopened["corridor"]["stack"]["flow_id"], id);
        let excluded = document(run(
            &root,
            &cache,
            &[],
            &["show", "--id", id],
            &[
                "--contains",
                "__absent_provenance_filter__",
                "--all",
                "--format",
                "json",
            ],
        ));
        assert!(excluded["corridor"].is_null(), "{excluded}");
        assert!(!excluded.to_string().contains(id), "{excluded}");
    }
    let unknown = run(
        &root,
        &cache,
        &[],
        &["inspect-graph"],
        &[
            "--from",
            "entry",
            "--to",
            "alpha",
            "--flow",
            "F:0000000000000000",
            "--contains",
            "__absent_provenance_filter__",
            "--format",
            "json",
        ],
    );
    assert!(!unknown.status.success(), "unknown explicit ids still fail");
}

#[test]
fn existing_flow_and_group_ids_can_be_excluded_without_becoming_unknown() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("workspace");
    let cache = temp.path().join("cache");
    fixture(&root);
    let report = document(run(
        &root,
        &cache,
        &[],
        &["inspect-graph"],
        &["--query", "alpha", "--kind", "decl", "--all", "--format", "json"],
    ));
    for (flag, id) in [
        ("--flow", &report["decl_hits"][0]["flows"][0]["flow_id"]),
        ("--group", &report["decl_hits"][0]["groups"][0]["group_id"]),
    ] {
        let id = id.as_str().expect("fixture must emit a structural id");
        for _ in 0..2 {
            let selected = document(run(
                &root,
                &cache,
                &[],
                &["inspect-graph"],
                &[
                    "--query",
                    "alpha",
                    "--kind",
                    "decl",
                    flag,
                    id,
                    "--contains",
                    "__absent_id_filter__",
                    "--all",
                    "--format",
                    "json",
                ],
            ));
            assert_eq!(selected["decl_hits"], json!([]), "{selected}");
            let selected = document(run(
                &root,
                &cache,
                &[],
                &["show", "--id", id],
                &["--contains", "__absent_id_filter__", "--all", "--format", "json"],
            ));
            assert!(!selected.to_string().contains(id), "{selected}");
        }
    }
    let unknown = run(
        &root,
        &cache,
        &[],
        &["inspect-graph"],
        &[
            "--query",
            "alpha",
            "--kind",
            "decl",
            "--group",
            "G:0000000000000000",
            "--contains",
            "__absent_id_filter__",
            "--format",
            "json",
        ],
    );
    assert!(!unknown.status.success(), "unknown explicit groups still fail");
}

#[test]
fn every_browse_command_accumulates_global_filters_and_preserves_exact_rows() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("workspace");
    let cache = temp.path().join("cache");
    fixture(&root);
    for command in [
        vec!["defs"],
        vec!["entrypoints"],
        vec!["calls"],
        vec!["imports"],
        vec!["vars"],
        vec!["strings"],
        vec!["comments"],
        vec!["args"],
        vec!["operations"],
        vec!["classes"],
        vec!["refs", "--symbol", "alpha"],
        vec!["search", "--query", "alpha"],
    ] {
        let base = document(run(&root, &cache, &[], &command, &["--all", "--format", "json"]));
        let rows = base["rows"].as_array().unwrap();
        assert!(!rows.is_empty(), "fixture must exercise {}: {base}", command[0]);
        let expected: Vec<_> = rows
            .iter()
            .filter(|row| matches(row, "app.py"))
            .map(facts)
            .collect();
        let selected = document(run(
            &root,
            &cache,
            &[],
            &command,
            &[
                "--contains",
                "APP.PY",
                "--contains",
                "app.py",
                "--all",
                "--format",
                "json",
            ],
        ));
        assert_eq!(
            selected["rows"]
                .as_array()
                .unwrap()
                .iter()
                .map(facts)
                .collect::<Vec<_>>(),
            expected,
            "{}",
            command[0]
        );
        assert_eq!(selected["page"]["total_rows"], expected.len(), "{}", command[0]);
        let none = document(run(
            &root,
            &cache,
            &["--contains", "__missing_filter_fact_8241__"],
            &command,
            &["--contains", "app.py", "--all", "--format", "json"],
        ));
        assert_eq!(
            none["rows"],
            json!([]),
            "ancestor inclusion was lost: {}",
            command[0]
        );
        let excluded = document(run(
            &root,
            &cache,
            &["--not-contains", "APP.PY"],
            &command,
            &[
                "--not-contains",
                "__missing_filter_fact_8241__",
                "--all",
                "--format",
                "json",
            ],
        ));
        let expected: Vec<_> = rows
            .iter()
            .filter(|row| !matches(row, "app.py"))
            .map(facts)
            .collect();
        assert_eq!(
            excluded["rows"]
                .as_array()
                .unwrap()
                .iter()
                .map(facts)
                .collect::<Vec<_>>(),
            expected,
            "ancestor exclusion was lost: {}",
            command[0]
        );
    }
}

#[test]
fn strings_and_comments_regex_filter_once_with_text_json_and_cache_parity() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("workspace");
    let cache = temp.path().join("cache");
    fixture(&root);
    for command in ["strings", "comments"] {
        for flags in [
            vec!["--contains", "ALPHA", "--contains", "TOKEN"],
            vec![
                "--contains",
                "Alpha.*Token",
                "--contains",
                "^app\\.py$",
                "--regex",
            ],
            vec![
                "--contains",
                "(?i)ALPHA.*TOKEN",
                "--regex",
                "--not-contains",
                "Beta",
            ],
        ] {
            let mut json_flags = flags.clone();
            json_flags.extend(["--all", "--format", "json"]);
            let first = document(run(&root, &cache, &[], &[command], &json_flags));
            assert_eq!(first["rows"].as_array().unwrap().len(), 1, "{command}: {first}");
            assert!(first["rows"][0]["text"].as_str().unwrap().contains("Alpha Token"));
            let warm = document(run(&root, &cache, &[], &[command], &json_flags));
            assert_eq!(first, warm, "warm {command}");
            let cold = document(run(&root, &cache, &["--no-cache"], &[command], &json_flags));
            assert_eq!(facts(&first["rows"][0]), facts(&cold["rows"][0]));
            let text = run(&root, &cache, &[], &[command], &flags);
            assert!(text.status.success());
            let text = String::from_utf8(text.stdout).unwrap();
            assert!(text.contains("Alpha Token"), "{text}");
            assert!(!text.contains("Beta Other"), "{text}");
        }
        let invalid = run(&root, &cache, &[], &[command], &["--contains", "[", "--regex"]);
        assert!(!invalid.status.success());
        assert!(String::from_utf8_lossy(&invalid.stderr).contains("invalid --contains regex"));
    }
}

#[test]
fn secondary_filtered_pages_do_not_accept_another_views_cursor() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("workspace");
    let cache = temp.path().join("cache");
    fixture(&root);
    let first = document(run(
        &root,
        &cache,
        &[],
        &["defs"],
        &[
            "--contains",
            "app.py",
            "--limit",
            "1",
            "--context",
            "1m",
            "--format",
            "json",
        ],
    ));
    let next = first["page"]["next_cursor"]
        .as_str()
        .expect("fixture has multiple pages");
    let second = document(run(
        &root,
        &cache,
        &[],
        &["defs"],
        &[
            "--contains",
            "app.py",
            "--limit",
            "1",
            "--context",
            "1m",
            "--page",
            next,
            "--format",
            "json",
        ],
    ));
    assert_eq!(second["page"]["number"], 2);
    assert_ne!(facts(&first["rows"][0]), facts(&second["rows"][0]));
    let wrong = run(
        &root,
        &cache,
        &[],
        &["defs"],
        &[
            "--contains",
            "client.py",
            "--limit",
            "1",
            "--context",
            "1m",
            "--page",
            first["page"]["cursor"].as_str().unwrap(),
            "--format",
            "json",
        ],
    );
    assert!(
        !wrong.status.success(),
        "a cursor must belong to the selected view"
    );
}

#[test]
fn entrypoint_file_filter_preserves_cross_module_callers_and_absolute_paths() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("workspace");
    let cache = temp.path().join("cache");
    fixture(&root);
    let all = document(run(
        &root,
        &cache,
        &[],
        &["entrypoints"],
        &["--all", "--format", "json"],
    ));
    let expected: Vec<_> = all["rows"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|row| row["file"] == "app.py")
        .map(facts)
        .collect();
    assert!(!expected.is_empty());
    assert!(expected.iter().all(|row| row["name"] != "alpha"));
    let absolute = root.join("app.py").canonicalize().unwrap();
    for file in ["app.py", absolute.to_str().unwrap()] {
        let selected = document(run(
            &root,
            &cache,
            &["--no-cache"],
            &["entrypoints"],
            &["--file", file, "--all", "--format", "json"],
        ));
        assert_eq!(
            selected["rows"]
                .as_array()
                .unwrap()
                .iter()
                .map(facts)
                .collect::<Vec<_>>(),
            expected,
            "{file}: {selected}"
        );
    }
}

#[test]
#[allow(clippy::unicode_not_nfc)] // Deliberately test decomposed Unicode scalar counts.
fn lexical_length_filters_count_unicode_bodies_not_delimiters() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("workspace");
    let cache = temp.path().join("cache");
    std::fs::create_dir(&root).unwrap();
    std::fs::write(
        root.join("app.js"),
        "const empty = \"\"; const unicode = \"é🦀é\"; const escape = \"\\n\";\n/**/\n/*é🦀é*/\n/* */\n",
    )
    .unwrap();
    for command in ["strings", "comments"] {
        let base = document(run(
            &root,
            &cache,
            &[],
            &[command],
            &["--all", "--format", "json"],
        ));
        let rows = base["rows"].as_array().unwrap();
        assert!(rows.iter().any(|row| row["content_len"] == 0));
        assert!(rows.iter().any(|row| row["content_len"] == 4));
        for minimum in [0, 1, 2, 4, 5] {
            let threshold = minimum.to_string();
            let expected: Vec<_> = rows
                .iter()
                .filter(|row| row["content_len"].as_u64().unwrap() >= minimum)
                .map(facts)
                .collect();
            for prefix in [&[][..], &["--no-cache"][..]] {
                let selected = document(run(
                    &root,
                    &cache,
                    prefix,
                    &[command],
                    &["--min-len", &threshold, "--all", "--format", "json"],
                ));
                assert_eq!(
                    selected["rows"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(facts)
                        .collect::<Vec<_>>(),
                    expected,
                    "{command} min={minimum}"
                );
            }
        }
    }
}

#[test]
fn inspect_cursors_include_command_local_selectors() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("workspace");
    let cache = temp.path().join("cache");
    fixture(&root);
    let calls = document(run(
        &root,
        &cache,
        &[],
        &["inspect-graph"],
        &[
            "--query",
            "a",
            "--kind",
            "call",
            "--compact",
            "--context",
            "100",
            "--format",
            "json",
        ],
    ));
    let declarations = document(run(
        &root,
        &cache,
        &[],
        &["inspect-graph"],
        &[
            "--query",
            "a",
            "--kind",
            "decl",
            "--compact",
            "--context",
            "100",
            "--format",
            "json",
        ],
    ));
    let call_cursor = calls["page"]["cursor"].as_str().unwrap();
    assert_ne!(calls["page"]["cursor"], declarations["page"]["cursor"]);
    let wrong = run(
        &root,
        &cache,
        &[],
        &["inspect-graph"],
        &[
            "--query",
            "a",
            "--kind",
            "decl",
            "--compact",
            "--context",
            "100",
            "--page",
            call_cursor,
            "--format",
            "json",
        ],
    );
    assert!(
        !wrong.status.success(),
        "inspect must reject another kind's cursor"
    );
}
