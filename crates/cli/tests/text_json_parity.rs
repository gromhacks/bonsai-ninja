//! Text/JSON parity across every command family.
//!
//! The text view is a renderer over the same canonical document that
//! `--format json` prints. These tests run each command in both formats on
//! the python micro fixture and assert, in both directions, that the
//! identity-bearing facts agree:
//!
//! - every identity fact in JSON (names, files, rule ids, stable ids) is
//!   printed by the text view, so a human never sees fewer objects than a
//!   script does;
//! - every stable id and every `file:line` location printed by the text view
//!   exists in JSON, so a script never lacks a fact a human can read.
//!
//! Formatting-only differences (borders, wrapping, colour, labels) are
//! ignored by comparing whitespace-normalised text.

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::process::Command;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("repository root")
}

fn workspace() -> String {
    repo_root()
        .join("test-fixtures/languages/python/micro")
        .to_string_lossy()
        .into_owned()
}

fn rules_dir() -> String {
    repo_root()
        .join("security-patterns")
        .to_string_lossy()
        .into_owned()
}

fn run(args: &[&str]) -> String {
    let output = Command::new(env!("CARGO_BIN_EXE_bonsai-ninja"))
        .args(args)
        .args(["--no-color", "--no-progress"])
        .env("COLUMNS", "200")
        .env_remove("BONSAI_CONTEXT")
        .output()
        .unwrap_or_else(|error| panic!("run bonsai-ninja {args:?}: {error}"));
    assert!(
        output.status.success(),
        "bonsai-ninja {args:?} failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("UTF-8 stdout")
}

/// Whitespace-insensitive haystack: table wrapping may split a long value
/// across lines, but never changes its characters.
fn squash(text: &str) -> String {
    text.chars().filter(|ch| !ch.is_whitespace()).collect()
}

/// JSON keys whose string values are identity facts a human must be able
/// to read in the text view.
const IDENTITY_KEYS: &[&str] = &[
    "name",
    "file",
    "rule_id",
    "finding_id",
    "flow_id",
    "group_id",
    "representative_flow_id",
    "taint_id",
    "edge_id",
    "symbol",
    "function",
    "callee_name",
    "caller_name",
    "origin_function",
    "enclosing_fn",
    "enclosing_function",
];

fn collect_identity_facts(value: &serde_json::Value, key: Option<&str>, out: &mut BTreeSet<String>) {
    match value {
        serde_json::Value::String(text) => {
            if key.is_some_and(|key| IDENTITY_KEYS.contains(&key)) && text.len() >= 2 {
                out.insert(text.clone());
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                collect_identity_facts(item, key, out);
            }
        }
        serde_json::Value::Object(fields) => {
            for (child_key, child) in fields {
                collect_identity_facts(child, Some(child_key), out);
            }
        }
        _ => {}
    }
}

fn collect_string_leaves(value: &serde_json::Value, out: &mut String) {
    match value {
        serde_json::Value::String(text) => {
            out.push_str(text);
            out.push('\n');
        }
        serde_json::Value::Array(items) => items.iter().for_each(|item| collect_string_leaves(item, out)),
        serde_json::Value::Object(fields) => {
            fields.values().for_each(|item| collect_string_leaves(item, out));
        }
        _ => {}
    }
}

fn collect_numbers(value: &serde_json::Value, out: &mut BTreeSet<u64>) {
    match value {
        serde_json::Value::Number(number) => {
            if let Some(number) = number.as_u64() {
                out.insert(number);
            }
        }
        serde_json::Value::Array(items) => items.iter().for_each(|item| collect_numbers(item, out)),
        serde_json::Value::Object(fields) => fields.values().for_each(|item| collect_numbers(item, out)),
        _ => {}
    }
}

/// Stable ids printed by the text view: `S:`, `F:`, `G:`, `E:`, `T:`, `N:`,
/// `R:` followed by at least eight lowercase hex digits. Page cursors (`P:`)
/// are footer chrome and are compared through the `page` object instead.
fn text_stable_ids(text: &str) -> BTreeSet<String> {
    let bytes = text.as_bytes();
    let mut ids = BTreeSet::new();
    let mut index = 0;
    while index + 2 < bytes.len() {
        let prefix = bytes[index];
        if matches!(prefix, b'S' | b'F' | b'G' | b'E' | b'T' | b'N' | b'R')
            && bytes[index + 1] == b':'
            && (index == 0 || !bytes[index - 1].is_ascii_alphanumeric())
        {
            let start = index + 2;
            let mut end = start;
            while end < bytes.len() && bytes[end].is_ascii_hexdigit() && !bytes[end].is_ascii_uppercase() {
                end += 1;
            }
            if end - start >= 8 {
                ids.insert(text[index..end].to_string());
                index = end;
                continue;
            }
        }
        index += 1;
    }
    ids
}

/// `file.ext:LINE` locations printed by the text view.
fn text_locations(text: &str) -> BTreeSet<(String, u64)> {
    let mut locations = BTreeSet::new();
    for token in text.split(|ch: char| ch.is_whitespace() || matches!(ch, '(' | ')' | ',' | '[' | ']')) {
        let Some((file, rest)) = token.split_once(':') else {
            continue;
        };
        let Some(extension) = file.rsplit('.').next() else {
            continue;
        };
        if file == extension || !extension.chars().all(|ch| ch.is_ascii_alphanumeric()) || file.contains("::")
        {
            continue;
        }
        let line = rest.split(':').next().unwrap_or_default();
        if let Ok(line) = line.parse::<u64>() {
            if line > 0 {
                locations.insert((file.to_string(), line));
            }
        }
    }
    locations
}

fn assert_parity(label: &str, text_args: &[&str], json_args: &[&str]) {
    let text = run(text_args);
    let json_text = run(json_args);
    let json: serde_json::Value = serde_json::from_str(&json_text)
        .unwrap_or_else(|error| panic!("{label}: JSON invalid ({error}):\n{json_text}"));

    let squashed_text = squash(&text);
    let mut facts = BTreeSet::new();
    collect_identity_facts(&json, None, &mut facts);
    let missing_in_text = facts
        .iter()
        .filter(|fact| !squashed_text.contains(&squash(fact)))
        .cloned()
        .collect::<Vec<_>>();
    assert!(
        missing_in_text.is_empty(),
        "{label}: JSON identity facts absent from the text view: {missing_in_text:?}\n--- text ---\n{text}\n--- json ---\n{json_text}"
    );

    let mut json_strings = String::new();
    collect_string_leaves(&json, &mut json_strings);
    let squashed_json = squash(&json_strings);
    let missing_ids = text_stable_ids(&text)
        .into_iter()
        .filter(|id| !squashed_json.contains(id.as_str()))
        .collect::<Vec<_>>();
    assert!(
        missing_ids.is_empty(),
        "{label}: stable ids printed by text are absent from JSON: {missing_ids:?}\n--- text ---\n{text}\n--- json ---\n{json_text}"
    );

    let mut numbers = BTreeSet::new();
    collect_numbers(&json, &mut numbers);
    let missing_locations = text_locations(&text)
        .into_iter()
        .filter(|(file, line)| !(squashed_json.contains(&squash(file)) && numbers.contains(line)))
        .collect::<Vec<_>>();
    assert!(
        missing_locations.is_empty(),
        "{label}: locations printed by text are absent from JSON: {missing_locations:?}\n--- text ---\n{text}\n--- json ---\n{json_text}"
    );
}

fn parity(label: &str, base: &[&str]) {
    let json_args = [base, &["--format", "json"]].concat();
    assert_parity(label, base, &json_args);
}

#[test]
fn syntax_inventories_agree_between_text_and_json() {
    let ws = workspace();
    for (label, args) in [
        ("defs", vec!["defs", ws.as_str(), "--all"]),
        ("classes", vec!["classes", ws.as_str(), "--all"]),
        ("entrypoints", vec!["entrypoints", ws.as_str(), "--all"]),
        ("imports", vec!["imports", ws.as_str(), "--all"]),
        ("calls", vec!["calls", ws.as_str(), "--all"]),
        ("args", vec!["args", ws.as_str(), "--all"]),
        (
            "refs",
            vec!["refs", ws.as_str(), "--symbol", "verify_token", "--all"],
        ),
        ("strings", vec!["strings", ws.as_str(), "--all"]),
        ("comments", vec!["comments", ws.as_str(), "--all"]),
        ("vars", vec!["vars", ws.as_str(), "--all"]),
        ("operations", vec!["operations", ws.as_str(), "--all"]),
        (
            "search",
            vec!["search", ws.as_str(), "--query", "verify", "--all"],
        ),
    ] {
        parity(label, &args);
    }
}

#[test]
fn navigation_commands_agree_between_text_and_json() {
    let ws = workspace();
    for (label, args) in [
        (
            "inspect-graph",
            vec!["inspect-graph", ws.as_str(), "--query", "verify_token", "--all"],
        ),
        ("read-file", vec!["read-file", ws.as_str(), "gateway.py", "--all"]),
    ] {
        parity(label, &args);
    }
}

#[test]
fn compiler_dump_commands_agree_between_text_and_json() {
    let ws = workspace();
    for (label, args) in [
        ("dump-callgraph", vec!["dump-callgraph", ws.as_str(), "--all"]),
        ("dump-edges", vec!["dump-edges", ws.as_str(), "--all"]),
        ("dump-resolution", vec!["dump-resolution", ws.as_str(), "--all"]),
        (
            "dump-resolve",
            vec!["dump-resolve", ws.as_str(), "--name", "verify_token"],
        ),
        (
            "dump-taint",
            vec!["dump-taint", ws.as_str(), "--source", "handle_request", "--all"],
        ),
        (
            "dump-hir",
            vec!["dump-hir", ws.as_str(), "--symbol", "handle_request"],
        ),
        (
            "dump-cfg",
            vec!["dump-cfg", ws.as_str(), "--symbol", "handle_request"],
        ),
        ("diagnostics", vec!["diagnostics", ws.as_str()]),
        ("index", vec!["index", ws.as_str()]),
    ] {
        parity(label, &args);
    }
}

#[test]
fn security_commands_agree_between_text_and_json() {
    let ws = workspace();
    let rules = rules_dir();
    for (label, args) in [
        (
            "security sources",
            vec![
                "security",
                ws.as_str(),
                "sources",
                "--rules-dir",
                rules.as_str(),
                "--all",
            ],
        ),
        (
            "security sinks",
            vec![
                "security",
                ws.as_str(),
                "sinks",
                "--rules-dir",
                rules.as_str(),
                "--all",
            ],
        ),
        (
            "security sanitizers",
            vec![
                "security",
                ws.as_str(),
                "sanitizers",
                "--rules-dir",
                rules.as_str(),
                "--all",
            ],
        ),
        (
            "security deps",
            vec![
                "security",
                ws.as_str(),
                "deps",
                "--rules-dir",
                rules.as_str(),
                "--all",
            ],
        ),
        (
            "security pack",
            vec![
                "security",
                ws.as_str(),
                "pack",
                "--rules-dir",
                rules.as_str(),
                "--lang",
                "python",
                "--category",
                "insecure-deserialization",
                "--all",
            ],
        ),
        (
            "security taint-analysis",
            vec![
                "security",
                ws.as_str(),
                "taint-analysis",
                "--rules-dir",
                rules.as_str(),
                "--all",
            ],
        ),
        (
            "security source-analysis",
            vec![
                "security",
                ws.as_str(),
                "source-analysis",
                "--rules-dir",
                rules.as_str(),
                "--source",
                "^python\\.flask\\.",
                "--all",
            ],
        ),
        (
            "security sink-analysis",
            vec![
                "security",
                ws.as_str(),
                "sink-analysis",
                "--rules-dir",
                rules.as_str(),
                "--sink",
                "^python\\.cmdi\\.",
                "--all",
            ],
        ),
    ] {
        parity(label, &args);
    }
}
