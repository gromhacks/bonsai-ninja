//! Real API-shaped contracts independent of the rule's own matching examples.
//! Fixtures are analyzed, never executed. A nearby safe case must stay quiet.

use serde_json::Value;
use std::path::Path;
use std::process::Command;

fn run(root: &Path, cache: &Path, command: &str, no_cache: bool) -> Value {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_bonsai-ninja"));
    cmd.arg("security")
        .arg(root)
        .arg(command)
        .args([
            "--all",
            "--format",
            "json",
            "--no-color",
            "--no-progress",
            "--rules-dir",
        ])
        .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../security-patterns"))
        .env("BONSAI_WORKSPACE_DIR", cache);
    if command == "taint-analysis" {
        cmd.args(["--profile", "all", "--show-sanitized", "--include-pattern-only"]);
    }
    if no_cache {
        cmd.arg("--no-cache");
    }
    let output = cmd.output().expect("run analysis");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: Value = serde_json::from_slice(&output.stdout).expect("canonical JSON");
    assert_eq!(value["analysis_complete"], true, "{value}");
    assert_eq!(value["analysis_incomplete_reasons"], serde_json::json!([]));
    assert_eq!(value["page"]["is_last"], true, "fixture must be exhaustive");
    value
}

fn fixture(language: &str) -> tempfile::TempDir {
    let root = tempfile::tempdir().expect("isolated workspace");
    let source = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/rule_context")
        .join(language);
    for entry in std::fs::read_dir(source).expect("fixtures") {
        let entry = entry.expect("fixture entry");
        std::fs::copy(entry.path(), root.path().join(entry.file_name())).expect("copy fixture");
    }
    root
}

#[test]
fn reviewed_language_flows_preserve_unsafe_contexts_and_complete_coverage() {
    type Locations<'a> = &'a [(&'a str, &'a [u64])];
    let cases: &[(&str, Locations<'_>)] = &[
        ("csharp", &[("Controller.cs", &[5, 8, 11])]),
        ("dart", &[("app.dart", &[3, 6])]),
        ("elixir", &[("app.ex", &[4, 7])]),
        ("erlang", &[("app.erl", &[5, 8])]),
        ("go", &[("app.go", &[8, 11])]),
        ("java", &[("Controller.java", &[7, 10])]),
        (
            "javascript",
            &[("app.js", &[5, 8, 11, 14]), ("constructors.js", &[4, 7])],
        ),
        ("kotlin", &[("App.kt", &[6, 9]), ("Inferred.kt", &[6])]),
        ("lua", &[("app.lua", &[6, 11])]),
        ("objc", &[("app.m", &[10])]),
        ("perl", &[("app.pl", &[4, 8, 12]), ("pipe.pl", &[4, 8])]),
        ("php", &[("app.php", &[3, 6, 9, 12, 15, 18])]),
        (
            "python",
            &[("app.py", &[12, 16, 20, 24, 28]), ("fastapi_app.py", &[6, 9])],
        ),
        ("ruby", &[("app.rb", &[5, 8])]),
        ("rust", &[]),
        ("scala", &[("Controller.scala", &[8, 12])]),
        ("swift", &[("DeepLink.swift", &[8, 14])]),
        (
            "typescript",
            &[("app.ts", &[5, 8, 11, 14]), ("constructors.ts", &[4, 7])],
        ),
    ];
    let mut errors = Vec::new();
    for (language, files) in cases {
        let root = fixture(language);
        let cache = tempfile::tempdir().unwrap();
        let value = run(root.path(), cache.path(), "taint-analysis", true);
        let rows = value["rows"].as_array().expect("rows");
        for (file, lines) in *files {
            for line in *lines {
                if !rows.iter().any(|row| {
                    row["sink"]["file"] == *file
                        && row["sink"]["line"] == *line
                        && row["status"] == "unsanitized"
                }) {
                    errors.push(format!(
                        "{language}/{file}:{line} lacks an unsanitized flow: {value}"
                    ));
                }
            }
        }
        for row in rows {
            let expected = files.iter().any(|(file, lines)| {
                row["sink"]["file"] == *file
                    && row["sink"]["line"]
                        .as_u64()
                        .is_some_and(|line| lines.contains(&line))
            });
            if !expected || row["status"] != "unsanitized" {
                errors.push(format!(
                    "{language}: unexpected finding or sanitizer credit: {row}"
                ));
            }
            assert!(row["finding_id"].as_str().is_some_and(|id| id.starts_with("S:")));
            assert!(row["representative_flow_id"]
                .as_str()
                .is_some_and(|id| id.starts_with("F:")));
            assert!(row["group_id"].as_str().is_some_and(|id| id.starts_with("G:")));
            assert!(
                row["source"]["rule_id"].as_str().is_some_and(|id| !id.is_empty()),
                "{row}"
            );
        }
    }
    assert!(errors.is_empty(), "{}", errors.join("\n"));
}

#[test]
fn curl_tls_options_are_not_ssrf_url_sinks() {
    for (language, file) in [("c", "tls.c"), ("cpp", "tls.cpp")] {
        let root = fixture(language);
        let cache = tempfile::tempdir().unwrap();
        let result = run(root.path(), cache.path(), "sinks", true);
        let rows = result["rows"].as_array().unwrap();
        assert_eq!(rows.len(), 3, "{language}: {result}");
        for line in [4, 5, 6] {
            assert!(
                rows.iter()
                    .any(|row| row["file"] == file && row["line"] == line && row["tag"] == "weak-tls"),
                "{result}"
            );
        }
    }
}

#[test]
fn non_crediting_encoders_are_transforms_in_json_and_text() {
    let root = fixture("javascript");
    let cache = tempfile::tempdir().unwrap();
    let result = run(root.path(), cache.path(), "taint-analysis", true);
    let encoded = result["rows"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["sink"]["file"] == "app.js" && row["sink"]["line"] == 5)
        .unwrap();
    assert_eq!(encoded["status"], "unsanitized");
    assert!(
        encoded["taint_transforms_seen"]
            .as_array()
            .unwrap()
            .iter()
            .any(|matched| matched["rule_id"] == "javascript.sanitizer.encodeuri"),
        "{encoded}"
    );
    assert!(
        encoded
            .get("sanitizers_seen")
            .is_none_or(|value| value.as_array().unwrap().is_empty()),
        "{encoded}"
    );
    let output = Command::new(env!("CARGO_BIN_EXE_bonsai-ninja"))
        .arg("security")
        .arg(root.path())
        .arg("taint-analysis")
        .args([
            "--profile",
            "all",
            "--tag",
            "open-redirect",
            "--all",
            "--no-color",
            "--no-progress",
            "--rules-dir",
        ])
        .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../security-patterns"))
        .env("BONSAI_WORKSPACE_DIR", cache.path())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(
        text.contains("TAINT TRANSFORM:") && text.contains("taint preserved by —"),
        "{text}"
    );
    assert!(
        !text.contains("SANITIZER:  javascript.sanitizer.encodeuri")
            && !text.contains("sanitized via — encodeURI"),
        "{text}"
    );
}

#[test]
fn safe_execution_and_parameter_binding_controls_remain_quiet() {
    let cases = [
        (
            "safe.py",
            r#"import subprocess
from fastapi import FastAPI, Depends
app = FastAPI()
def local_command(): return '/usr/bin/true'
@app.get('/safe')
def safe(cmd: str = Depends(local_command)):
    subprocess.run(cmd, shell=False)
@app.get('/argument')
def argument(value: str):
    subprocess.run(['/bin/echo', value], shell=False)
@app.get('/assigned')
def assigned(value: str):
    arguments = ['/bin/echo', value]
    copied = arguments
    subprocess.run(copied, shell=False)
"#,
        ),
        (
            "safe.js",
            r#"const express = require('express');
const child_process = require('child_process');
const app = express();
app.get('/safe', (req, res) => {
  child_process.spawn('/bin/echo', [req.query.value], {shell: false});
  res.redirect('/home');
});
"#,
        ),
        (
            "safe.php",
            r#"<?php
function safe(PDO $db) {
    $db->exec('DELETE FROM expired_sessions');
    header('Location: /home');
    header('X-Request-Id: ' . $_GET['id']);
    echo htmlspecialchars($_GET['html']);
}
"#,
        ),
    ];
    for (file, code) in cases {
        let root = tempfile::tempdir().unwrap();
        let cache = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join(file), code).unwrap();
        let result = run(root.path(), cache.path(), "taint-analysis", true);
        if file == "safe.php" {
            assert_eq!(
                result["rows"].as_array().unwrap().len(),
                1,
                "HTML escaping remains a credited protection: {result}"
            );
        }
        assert!(
            result["rows"]
                .as_array()
                .unwrap()
                .iter()
                .all(|row| row["status"] == "sanitized"),
            "{file}: {result}"
        );
    }
}

#[test]
fn fixed_local_redirect_prefixes_do_not_credit_ambiguous_authority_prefixes() {
    for (language, file) in [
        ("python", "app.py"),
        ("javascript", "app.js"),
        ("typescript", "app.ts"),
    ] {
        for (prefix, unsafe_target) in [
            ("/next?to=", false),
            ("/a", false),
            ("/", true),
            ("//", true),
            ("/\\", true),
            ("/\t", true),
            ("/\n", true),
            ("/\r", true),
        ] {
            let literal = serde_json::to_string(prefix).unwrap();
            let code = if language == "python" {
                format!("from flask import Flask, request, redirect\napp = Flask(__name__)\n@app.route('/')\ndef route():\n    return redirect({literal} + request.args.get('next'))\n")
            } else {
                format!("const express = require('express');\nconst app = express();\napp.get('/', (req, res) => res.redirect({literal} + req.query.next));\n")
            };
            let root = tempfile::tempdir().unwrap();
            let cache = tempfile::tempdir().unwrap();
            std::fs::write(root.path().join(file), code).unwrap();
            let result = run(root.path(), cache.path(), "taint-analysis", true);
            let rows = result["rows"].as_array().unwrap();
            assert_eq!(
                rows.len(),
                usize::from(unsafe_target),
                "{language} prefix {prefix:?}: {result}"
            );
            assert!(rows.iter().all(|row| row["status"] == "unsanitized"), "{result}");
        }
    }
}

#[test]
fn ignored_nested_workspace_cached_and_fresh_security_facts_agree_after_changes() {
    let repository = tempfile::tempdir().unwrap();
    let git = |args: &[&str]| {
        Command::new("git")
            .arg("-C")
            .arg(repository.path())
            .args(args)
            .output()
            .unwrap()
    };
    assert!(git(&["init", "-q"]).status.success());
    std::fs::write(repository.path().join(".gitignore"), "/scratch/\n").unwrap();
    assert!(git(&["add", ".gitignore"]).status.success());
    assert!(git(&[
        "-c",
        "user.name=Bonsai Test",
        "-c",
        "user.email=bonsai@example.invalid",
        "commit",
        "-qm",
        "fixture"
    ])
    .status
    .success());
    let root = repository.path().join("scratch");
    std::fs::create_dir(&root).unwrap();
    let cache = tempfile::tempdir().unwrap();
    let code = "from flask import request\nimport os\ndef run(): os.system(request.args.get('cmd'))\n";
    std::fs::write(root.join("first.py"), code).unwrap();
    let initial = run(&root, cache.path(), "taint-analysis", false);
    assert_eq!(initial["rows"].as_array().unwrap().len(), 1);
    for step in 0..4 {
        match step {
            0 => std::fs::write(root.join("second.py"), code).unwrap(),
            1 => std::fs::write(root.join("first.py"), "def clean(): return 1\n").unwrap(),
            2 => std::fs::rename(root.join("second.py"), root.join("renamed.py")).unwrap(),
            _ => std::fs::remove_file(root.join("renamed.py")).unwrap(),
        }
        let cached = run(&root, cache.path(), "taint-analysis", false);
        let fresh = run(&root, cache.path(), "taint-analysis", true);
        assert_eq!(
            cached["rows"], fresh["rows"],
            "cache diverged after mutation {step}"
        );
        assert_eq!(cached["rows"].as_array().unwrap().len(), [2, 1, 1, 0][step]);
    }
}
