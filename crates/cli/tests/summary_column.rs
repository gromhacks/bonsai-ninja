//! Per-language end-to-end tests for the `--summaries` column.
//!
//! For every `examples/{lang}/micro` fixture we run each browse
//! command with `--summaries --format json` and assert:
//!
//! * the `summaries` column renders in the text table without crashing;
//! * JSON rows expose the same IDs as a machine-readable `summary_ids` array;
//! * for the `defs` command specifically, at least one decl in the
//!   workspace carries a valid `F:<16-hex>` summary id (content-hash
//!   `F:` + 16 lowercase hex chars). Decls are the most reliable
//!   surface per-language — every micro fixture has at least one
//!   callable — so they're the right
//!   canary that compiler symbol identities are producing IDs for the
//!   adapter under test. Other browse commands (`vars`, `strings`,
//!   `args`, `classes`, `imports`) legitimately emit zero rows on
//!   some languages (e.g. Elixir has no re-assignable vars, Erlang
//!   has no classes); those tests just smoke-check that the flag
//!   doesn't error.
//!
//! Tests skip silently when the release binary hasn't been built.
//!
//! # Why per-language
//!
//! The `--summaries` column threads through compiler declaration identities.
//! A regression in any
//! adapter's decl-emission (wrong span, wrong symbol id, missing
//! method scoping) shows up here as either zero summary labels in
//! places where we expect them, or a malformed label that doesn't
//! match the `F:<16-hex>` pattern.
//!
//! See `crates/browse/src/summary_labels.rs` for the annotator these tests
//! exercise.

use std::path::PathBuf;
use std::process::Command;

const LANGUAGES: &[&str] = &[
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
    if p.exists() {
        Some(p)
    } else {
        eprintln!(
            "skipping --summaries integration test: release binary not built ({})",
            p.display()
        );
        None
    }
}

fn ws_for(lang: &str) -> Option<PathBuf> {
    let p = repo_root().join(format!("examples/{lang}/micro"));
    if p.is_dir() {
        Some(p)
    } else {
        eprintln!("skip: {} missing ({})", lang, p.display());
        None
    }
}

fn tempdir_for_test(name: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let root = std::env::temp_dir();
    for attempt in 0..100 {
        let path = root.join(format!("{name}-{}-{nanos:x}-{attempt}", std::process::id()));
        match std::fs::create_dir(&path) {
            Ok(()) => return path,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => panic!("create tempdir {}: {e}", path.display()),
        }
    }
    panic!("could not allocate tempdir for {name}");
}

fn write_summary_id_fan_in_workspace(root: &std::path::Path, callers: usize) {
    let mut source = String::from("def sink(value):\n    return value\n\n");
    for idx in 0..callers {
        source.push_str(&format!("def caller_{idx}(value):\n    return sink(value)\n\n"));
    }
    std::fs::write(root.join("app.py"), source).expect("write summary-id fan-in fixture");
}

/// Run `bonsai-ninja` with the given args + `--no-color` and
/// return stdout on success. Panics (fails the test) on non-zero
/// exit so a broken `--summaries` pipeline fails loudly rather than
/// silently producing empty output.
fn run(args: &[&str]) -> Option<String> {
    let bin = bin_path()?;
    let mut full: Vec<&str> = args.to_vec();
    full.push("--no-color");
    let out = Command::new(&bin)
        .args(&full)
        .env("COLUMNS", "200")
        .output()
        .expect("failed to run bonsai-ninja");
    assert!(
        out.status.success(),
        "bonsai-ninja {:?} exited with {}: stderr={}",
        args,
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    Some(String::from_utf8_lossy(&out.stdout).to_string())
}

/// Count canonical summary ids (`F:` plus 16 lowercase hex characters).
/// Exact-length checking prevents unrelated `F:` text from satisfying the
/// assertion.
fn count_summary_ids(s: &str) -> usize {
    let bytes = s.as_bytes();
    let mut count = 0usize;
    let mut i = 0;
    while i + 18 <= bytes.len() {
        if bytes[i] == b'F' && bytes[i + 1] == b':' && is_lower_hex(&bytes[i + 2..i + 18]) {
            // Confirm the next byte isn't another hex digit (so the
            // ID is exactly 16 chars, not 17+).
            let next_is_hex = bytes
                .get(i + 18)
                .is_some_and(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase());
            if !next_is_hex {
                count += 1;
                i += 18;
                continue;
            }
        }
        i += 1;
    }
    count
}

fn is_lower_hex(bytes: &[u8]) -> bool {
    bytes
        .iter()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
}

// -----------------------------------------------------------------------------
// Text-output assertion: every browse command must render a
// `summaries` header and exit successfully when `--summaries` is set.
// -----------------------------------------------------------------------------

fn assert_summaries_header(lang: &str, cmd: &str, extra: &[&str]) {
    let Some(ws) = ws_for(lang) else { return };
    let ws_str = ws.to_str().unwrap();
    let mut args = vec![cmd, ws_str, "--summaries"];
    args.extend_from_slice(extra);
    let Some(out) = run(&args) else { return };
    assert!(
        out.contains("summaries"),
        "{lang} {cmd}: missing `summaries` column header:\n{out}",
    );
}

#[test]
fn summaries_column_present_for_every_language_defs() {
    for &lang in LANGUAGES {
        assert_summaries_header(lang, "defs", &[]);
    }
}

#[test]
fn summaries_column_present_for_every_language_calls() {
    for &lang in LANGUAGES {
        assert_summaries_header(lang, "calls", &[]);
    }
}

#[test]
fn summaries_column_present_for_every_language_imports() {
    for &lang in LANGUAGES {
        assert_summaries_header(lang, "imports", &[]);
    }
}

#[test]
fn summaries_column_present_for_every_language_vars() {
    for &lang in LANGUAGES {
        assert_summaries_header(lang, "vars", &[]);
    }
}

#[test]
fn summaries_column_present_for_every_language_strings() {
    for &lang in LANGUAGES {
        assert_summaries_header(lang, "strings", &[]);
    }
}

#[test]
fn summaries_column_present_for_every_language_args() {
    for &lang in LANGUAGES {
        assert_summaries_header(lang, "args", &[]);
    }
}

#[test]
fn summaries_column_present_for_every_language_operations() {
    for &lang in LANGUAGES {
        assert_summaries_header(lang, "operations", &[]);
    }
}

#[test]
fn summaries_column_present_for_every_language_classes() {
    for &lang in LANGUAGES {
        assert_summaries_header(lang, "classes", &[]);
    }
}

#[test]
fn summaries_column_present_for_every_language_refs() {
    // refs requires a positional symbol. Pick one the fixtures all
    // at least try to expose. An empty result set is fine — what
    // we're testing is that the flag renders the header.
    for &lang in LANGUAGES {
        assert_summaries_header(lang, "refs", &["handle_request"]);
    }
}

#[test]
fn summaries_column_present_for_every_language_search() {
    for &lang in LANGUAGES {
        assert_summaries_header(lang, "search", &["--query", "request"]);
    }
}

// -----------------------------------------------------------------------------
// Canary: `defs --summaries` must produce at least one well-formed
// `F:<16-hex>` id per language. This is the test that catches
// adapter-level regressions (missing decl spans, bad symbol ids)
// that would let the `summaries` column exist but stay empty for a
// whole language.
// -----------------------------------------------------------------------------

#[test]
fn defs_summaries_column_populated_for_every_language() {
    for &lang in LANGUAGES {
        let Some(ws) = ws_for(lang) else { continue };
        let Some(out) = run(&["defs", ws.to_str().unwrap(), "--summaries"]) else {
            return;
        };
        let found = count_summary_ids(&out);
        assert!(
            found > 0,
            "{lang}: defs --summaries produced zero `F:<16-hex>` ids — adapter \
             may be emitting decls without valid spans / symbol ids.\nOutput:\n{out}",
        );
    }
}

// -----------------------------------------------------------------------------
// JSON-shape contract: without `--summaries` the native browse row is
// unchanged; with it, every row gains a machine-readable `summary_ids`
// array. Definitions must expose at least one canonical summary id for every
// supported language.
// -----------------------------------------------------------------------------

#[test]
fn summaries_flag_adds_machine_readable_ids_for_every_language() {
    for &lang in LANGUAGES {
        let Some(ws) = ws_for(lang) else { continue };
        let ws_str = ws.to_str().unwrap();
        for &cmd in &[
            "defs",
            "calls",
            "imports",
            "vars",
            "strings",
            "args",
            "operations",
            "classes",
        ] {
            let Some(plain_out) = run(&[cmd, ws_str, "--format", "json"]) else {
                return;
            };
            let plain: serde_json::Value = serde_json::from_str(&plain_out)
                .unwrap_or_else(|e| panic!("{lang} {cmd}: invalid plain JSON: {e}\n{plain_out}"));
            for row in plain.as_array().expect("browse JSON is an array") {
                assert!(
                    row.get("summary_ids").is_none(),
                    "{lang} {cmd}: default JSON must preserve the native row schema: {row}"
                );
            }

            let Some(summary_out) = run(&[cmd, ws_str, "--summaries", "--format", "json"]) else {
                return;
            };
            let summary: serde_json::Value = serde_json::from_str(&summary_out)
                .unwrap_or_else(|e| panic!("{lang} {cmd}: invalid summary JSON: {e}\n{summary_out}"));
            let rows = summary.as_array().expect("browse summary JSON is an array");
            for row in rows {
                assert!(
                    row.get("summary_ids").is_some_and(serde_json::Value::is_array),
                    "{lang} {cmd}: --summaries JSON row lacks summary_ids array: {row}"
                );
            }
            if cmd == "defs" {
                let ids = rows
                    .iter()
                    .filter_map(|row| row.get("summary_ids")?.as_array())
                    .flatten()
                    .filter_map(serde_json::Value::as_str)
                    .collect::<Vec<_>>();
                assert!(
                    ids.iter().any(|id| count_summary_ids(id) == 1),
                    "{lang}: defs --summaries JSON produced no canonical summary id: {summary_out}"
                );
            }
        }
    }
}

#[test]
fn summaries_remain_available_in_file_scoped_workspaces() {
    let Some(ws) = ws_for("python") else { return };
    let Some(out) = run(&[
        "defs",
        ws.to_str().unwrap(),
        "--file",
        "gateway.py",
        "--summaries",
        "--format",
        "json",
    ]) else {
        return;
    };
    let rows: serde_json::Value = serde_json::from_str(&out).expect("scoped defs JSON");
    let ids = rows
        .as_array()
        .expect("scoped defs array")
        .iter()
        .filter_map(|row| row.get("summary_ids")?.as_array())
        .flatten()
        .filter_map(serde_json::Value::as_str)
        .collect::<Vec<_>>();
    assert!(
        ids.iter().any(|id| count_summary_ids(id) == 1),
        "file-scoped --summaries was silently disabled: {out}"
    );
}

// -----------------------------------------------------------------------------
// Syntax inventory is the lightweight default. Summary-id annotation is
// explicit and adds the summary column only when requested.
// -----------------------------------------------------------------------------

#[test]
fn summaries_column_is_off_by_default() {
    for &lang in LANGUAGES {
        let Some(ws) = ws_for(lang) else { continue };
        let Some(out) = run(&["calls", ws.to_str().unwrap()]) else {
            return;
        };
        let header = out
            .lines()
            .find(|line| line.contains("caller") && line.contains("callee"))
            .unwrap_or("");
        assert!(
            !header.contains("summaries"),
            "{lang} calls: `summaries` column should be off by default: {out}"
        );
    }
}

#[test]
fn summaries_flag_enables_column() {
    for &lang in LANGUAGES {
        let Some(ws) = ws_for(lang) else { continue };
        let Some(out) = run(&["calls", ws.to_str().unwrap(), "--summaries"]) else {
            return;
        };
        let header_line = out
            .lines()
            .find(|line| line.contains("caller") && line.contains("callee"))
            .unwrap_or("");
        assert!(
            header_line.contains("summaries"),
            "{lang} calls --summaries: header is missing summaries: {header_line}"
        );
    }
}

#[test]
fn removed_flows_flag_is_rejected_instead_of_triggering_hidden_semantics() {
    let Some(bin) = bin_path() else { return };
    let Some(ws) = ws_for("python") else { return };
    let out = Command::new(bin)
        .args([
            "calls",
            ws.to_str().expect("workspace path"),
            "--flows",
            "--no-color",
        ])
        .output()
        .expect("run removed flag probe");
    assert!(!out.status.success(), "removed --flows flag must not be accepted");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("unexpected argument '--flows'"),
        "removed flag should fail through the normal CLI parser: {stderr}"
    );
}

// -----------------------------------------------------------------------------
// Summary-id parity: an id emitted by `calls --summaries` for a row
// inside function F must equal the structural id `inspect --query F`
// emits for that same function. Both codepaths use the shared compiler
// identity function; this test is the contract that they
// stay aligned.
//
// Regression guard for a bug where browse emitted ids hashed from
// `[handle_request]` while inspect emitted ids hashed from
// `[handle_request, get_user, verify_token, …]` — i.e. browse
// forgot to extend chains with the downstream callee closure, so
// a copy-pasted id wouldn't resolve with `inspect --flow`.
// -----------------------------------------------------------------------------

fn extract_summary_ids(s: &str) -> Vec<String> {
    let bytes = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i + 18 <= bytes.len() {
        if bytes[i] == b'F'
            && bytes[i + 1] == b':'
            && is_lower_hex(&bytes[i + 2..i + 18])
            && !bytes
                .get(i + 18)
                .is_some_and(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        {
            out.push(String::from_utf8_lossy(&bytes[i..i + 18]).to_string());
            i += 18;
        } else {
            i += 1;
        }
    }
    out
}

#[test]
fn browse_summary_ids_match_inspect_flow_ids() {
    let Some(ws) = ws_for("python") else { return };
    let ws_str = ws.to_str().unwrap();
    // Grab every callable summary id in the `calls` output.
    let Some(calls_out) = run(&["calls", ws_str, "--summaries"]) else {
        return;
    };
    let browse_ids: Vec<String> = extract_summary_ids(&calls_out);
    assert!(
        !browse_ids.is_empty(),
        "calls output had no summary ids to compare: {calls_out}"
    );

    // Query every callable so inspect emits the same bounded compiler
    // evidence identities.
    let Some(inspect_out) = run(&[
        "inspect",
        ws_str,
        "--query",
        ".*",
        "--regex",
        "--all",
        "--graph-flow",
    ]) else {
        return;
    };
    let inspect_ids: std::collections::HashSet<String> =
        extract_summary_ids(&inspect_out).into_iter().collect();
    assert!(
        !inspect_ids.is_empty(),
        "inspect output had no structural ids to compare: {inspect_out}"
    );

    // Every browse id must exist in inspect's set. The reverse
    // isn't required: inspect can legitimately surface flows for
    // functions that don't appear as an enclosing row in `calls`.
    for id in &browse_ids {
        assert!(
            inspect_ids.contains(id),
            "browse emitted summary id `{id}` that inspect does not recognise; \
             that means `inspect --flow {id}` would error when users paste \
             a summary id into inspect. browse ids: {browse_ids:?}\n\
             inspect ids: {inspect_ids:?}",
        );
    }
}

// -----------------------------------------------------------------------------
// Inspect `--flow` / `--group` can resolve a content-hash id
// without a companion `--query`. Guard for the bug where inspect
// required a query context and rejected every standalone
// `--flow F:<16-hex>` call with "no flow matching ...".
// -----------------------------------------------------------------------------

#[test]
fn inspect_flow_standalone_resolves() {
    let Some(ws) = ws_for("python") else { return };
    let ws_str = ws.to_str().unwrap();
    // Pick any callable summary id browse emits for the fixture.
    let Some(calls_out) = run(&["calls", ws_str, "--summaries"]) else {
        return;
    };
    let Some(target_id) = extract_summary_ids(&calls_out).into_iter().next() else {
        panic!("no summary id to pivot through: {calls_out}");
    };

    let Some(bin) = bin_path() else { return };
    let out = Command::new(&bin)
        .args(["inspect", ws_str, "--flow", &target_id, "--no-color"])
        .env("COLUMNS", "200")
        .output()
        .expect("failed to run bonsai-ninja");
    assert!(
        out.status.success(),
        "inspect --flow {target_id} (no query) must succeed; stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains(&target_id),
        "inspect --flow {target_id} did not echo the id back: {stdout}"
    );
}

// -----------------------------------------------------------------------------
// Fold regression: multiple syntax matches inside one callable share one
// bounded evidence identity and one source body.
// -----------------------------------------------------------------------------

#[test]
fn inspect_folds_occurrence_hits_sharing_a_flow() {
    let Some(ws) = ws_for("python") else { return };
    let ws_str = ws.to_str().unwrap();
    let Some(system_out) = run(&["inspect", ws_str, "--query", "os.system", "--graph-flow"]) else {
        return;
    };
    let Some(flow_id) = extract_summary_ids(&system_out).into_iter().next() else {
        panic!("inspect --query os.system emitted no structural id:\n{system_out}");
    };
    let Some(out) = run(&["inspect", ws_str, "--flow", &flow_id]) else {
        return;
    };

    for needle in &[
        "run_admin_command",
        "call os.system",
        "arg \"notify-admin \" + cmd",
    ] {
        assert!(
            out.contains(needle),
            "folded inspect lost context: `{needle}` missing from:\n{out}"
        );
    }

    assert!(
        !out.contains("handle_request → update_user → run_admin_command"),
        "summary lookup must not recursively materialize upstream paths:\n{out}"
    );

    // The `match points:` summary is the folded-view signature —
    // if it's absent the fold didn't kick in.
    assert!(
        out.contains("match points:"),
        "folded view should print `match points:` summary; got:\n{out}"
    );
}

// -----------------------------------------------------------------------------
// Per-command summary-id coverage on the python micro workspace.
//
// Every browse command that renders a `summaries` column must actually
// populate it for at least one row on a workspace with callable declarations.
// Each test pins the
// contract for a specific command — if adapter wiring or the
// `SummaryAnnotator` lookup breaks for one of them, only that test
// fires rather than all nine.
// -----------------------------------------------------------------------------

fn assert_browse_cmd_has_summary_ids(cmd: &str, extra: &[&str]) {
    let Some(ws) = ws_for("python") else { return };
    let ws_str = ws.to_str().unwrap();
    let mut args = vec![cmd, ws_str, "--summaries"];
    args.extend_from_slice(extra);
    let Some(out) = run(&args) else { return };
    let found = count_summary_ids(&out);
    assert!(
        found > 0,
        "python micro: `{cmd}` produced zero F:<16-hex> ids in the summaries column. \
         Either the annotator regressed or the adapter no longer wires symbols for \
         this row kind.\nOutput:\n{out}",
    );
}

#[test]
fn defs_summaries_column_populated() {
    assert_browse_cmd_has_summary_ids("defs", &[]);
}

#[test]
fn calls_summaries_column_populated() {
    assert_browse_cmd_has_summary_ids("calls", &[]);
}

#[test]
fn imports_summaries_column_populated() {
    // Imports at module scope never had an enclosing function, so
    // the old `labels_for(file, line)` path returned empty for
    // every import row. The symbol-name lookup
    // (`labels_for_symbol`) fixed this — `from .auth_service import
    // verify_token` now surfaces the imported callable's identity.
    // Guard against a regression back to the empty
    // column.
    assert_browse_cmd_has_summary_ids("imports", &[]);
}

#[test]
fn vars_summaries_column_populated() {
    assert_browse_cmd_has_summary_ids("vars", &[]);
}

#[test]
fn strings_summaries_column_populated() {
    assert_browse_cmd_has_summary_ids("strings", &[]);
}

#[test]
fn args_summaries_column_populated() {
    assert_browse_cmd_has_summary_ids("args", &[]);
}

#[test]
fn operations_summaries_column_populated() {
    assert_browse_cmd_has_summary_ids("operations", &["--kind", "call"]);
}

#[test]
fn classes_summaries_column_populated() {
    // python/micro doesn't define any classes, so refs/search are the
    // stronger coverage. Still run
    // the command to ensure a non-crashing execution path, but
    // tolerate zero ids (an empty column is valid when there is no class).
    let Some(ws) = ws_for("python") else { return };
    let Some(_out) = run(&["classes", ws.to_str().unwrap(), "--summaries"]) else {
        return;
    };
}

#[test]
fn refs_summaries_column_populated() {
    // `refs verify_token` — verify_token is called from
    // handle_request, so its call-site refs sit inside a callable with a
    // compiler summary id.
    assert_browse_cmd_has_summary_ids("refs", &["verify_token"]);
}

#[test]
fn search_summaries_column_populated() {
    // Search for `handle_request` — same reasoning as refs.
    assert_browse_cmd_has_summary_ids("search", &["--query", "handle_request"]);
}

#[test]
fn summary_column_is_constant_size_under_fan_in() {
    let root = tempdir_for_test("bonsai-summary-column-fan-in");
    write_summary_id_fan_in_workspace(&root, 40);

    let Some(out) = run(&["defs", root.to_str().unwrap(), "--name", "sink", "--summaries"]) else {
        return;
    };
    assert!(
        count_summary_ids(&out) > 0,
        "fan-in fixture should emit a summary id for sink:\n{out}"
    );
    assert!(
        count_summary_ids(&out) == 1,
        "one callable must have one summary id regardless of caller fan-in:\n{out}"
    );

    let _ = std::fs::remove_dir_all(root);
}
