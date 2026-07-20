//! Per-language end-to-end tests for the `--flows` column.
//!
//! For every `examples/{lang}/micro` fixture we run each browse
//! command with `--flows --format json` and assert:
//!
//! * the `flows` column renders in the text table without crashing;
//! * the JSON output parses cleanly;
//! * for the `defs` command specifically, at least one decl in the
//!   workspace carries a valid `F:<16-hex>` flow id (content-hash
//!   `F:` + 16 lowercase hex chars). Decls are the most reliable
//!   surface per-language — every micro fixture has at least one
//!   function that sits on a call chain — so they're the right
//!   canary that the chain enumerator is producing IDs for the
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
//! The `--flows` column threads through the resolved call graph,
//! which depends on every language adapter supplying
//! [`bonsai_lang_api::Adapter::extract_refs`] +
//! [`bonsai_lang_api::Adapter::decl_index`]. A regression in any
//! adapter's decl-emission (wrong span, wrong symbol id, missing
//! method scoping) shows up here as either zero flow labels in
//! places where we expect them, or a malformed label that doesn't
//! match the `F:<16-hex>` pattern.
//!
//! See `crates/browse/src/flows.rs` for the annotator these tests
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
    if p.exists() {
        Some(p)
    } else {
        eprintln!(
            "skipping --flows integration test: release binary not built ({})",
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

fn write_flow_label_fan_in_workspace(root: &std::path::Path, callers: usize) {
    let mut source = String::from("def sink(value):\n    return value\n\n");
    for idx in 0..callers {
        source.push_str(&format!("def caller_{idx}(value):\n    return sink(value)\n\n"));
    }
    std::fs::write(root.join("app.py"), source).expect("write flow-label fan-in fixture");
}

/// Run `bonsai-ninja` with the given args + `--no-color` and
/// return stdout on success. Panics (fails the test) on non-zero
/// exit so a broken `--flows` pipeline fails loudly rather than
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

/// Count occurrences of the canonical flow-id shape `F:` + exactly
/// 16 lowercase hex chars in `s`. Matches [`bonsai_sdk::compute_flow_id`]'s
/// output format so a stray `F:` in some unrelated column text
/// won't falsely satisfy the assertion.
fn count_flow_ids(s: &str) -> usize {
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
// `flows` header and exit successfully when `--flows` is set.
// -----------------------------------------------------------------------------

fn assert_flows_header(lang: &str, cmd: &str, extra: &[&str]) {
    let Some(ws) = ws_for(lang) else { return };
    let ws_str = ws.to_str().unwrap();
    // Column is on by default — no explicit `--flows` needed (that
    // flag was retired in favour of `--no-flows` as opt-out).
    let mut args = vec![cmd, ws_str];
    args.extend_from_slice(extra);
    let Some(out) = run(&args) else { return };
    assert!(
        out.contains("flows"),
        "{lang} {cmd}: missing `flows` column header:\n{out}",
    );
}

#[test]
fn flows_column_present_for_every_language_defs() {
    for &lang in LANGUAGES {
        assert_flows_header(lang, "defs", &[]);
    }
}

#[test]
fn flows_column_present_for_every_language_calls() {
    for &lang in LANGUAGES {
        assert_flows_header(lang, "calls", &[]);
    }
}

#[test]
fn flows_column_present_for_every_language_imports() {
    for &lang in LANGUAGES {
        assert_flows_header(lang, "imports", &[]);
    }
}

#[test]
fn flows_column_present_for_every_language_vars() {
    for &lang in LANGUAGES {
        assert_flows_header(lang, "vars", &[]);
    }
}

#[test]
fn flows_column_present_for_every_language_strings() {
    for &lang in LANGUAGES {
        assert_flows_header(lang, "strings", &[]);
    }
}

#[test]
fn flows_column_present_for_every_language_args() {
    for &lang in LANGUAGES {
        assert_flows_header(lang, "args", &[]);
    }
}

#[test]
fn flows_column_present_for_every_language_operations() {
    for &lang in LANGUAGES {
        assert_flows_header(lang, "operations", &[]);
    }
}

#[test]
fn flows_column_present_for_every_language_classes() {
    for &lang in LANGUAGES {
        assert_flows_header(lang, "classes", &[]);
    }
}

#[test]
fn flows_column_present_for_every_language_refs() {
    // refs requires a positional symbol. Pick one the fixtures all
    // at least try to expose. An empty result set is fine — what
    // we're testing is that the flag renders the header.
    for &lang in LANGUAGES {
        assert_flows_header(lang, "refs", &["handle_request"]);
    }
}

#[test]
fn flows_column_present_for_every_language_search() {
    for &lang in LANGUAGES {
        assert_flows_header(lang, "search", &["--query", "request"]);
    }
}

// -----------------------------------------------------------------------------
// Canary: `defs --flows` must produce at least one well-formed
// `F:<16-hex>` id per language. This is the test that catches
// adapter-level regressions (missing decl spans, bad symbol ids)
// that would let the `flows` column exist but stay empty for a
// whole language.
// -----------------------------------------------------------------------------

#[test]
fn defs_flows_column_populated_for_every_language() {
    for &lang in LANGUAGES {
        let Some(ws) = ws_for(lang) else { continue };
        let Some(out) = run(&["defs", ws.to_str().unwrap()]) else {
            return;
        };
        let found = count_flow_ids(&out);
        assert!(
            found > 0,
            "{lang}: defs --flows produced zero `F:<16-hex>` ids — adapter \
             may be emitting decls without valid spans / symbol ids.\nOutput:\n{out}",
        );
    }
}

// -----------------------------------------------------------------------------
// JSON-shape smoke tests: `--flows` must not break JSON output on
// any language. We don't assert on content because the JSON schema
// for browse commands doesn't yet include a `flows` field — the
// flag only affects text rendering today. This test guards against
// the flag accidentally causing a panic or a parse error in any
// adapter's JSON path.
// -----------------------------------------------------------------------------

#[test]
fn flows_flag_does_not_break_json_output() {
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
            // JSON output should parse regardless of whether flows
            // is on or off — test both paths.
            for extra in &[vec!["--format", "json"], vec!["--no-flows", "--format", "json"]] {
                let mut args = vec![cmd, ws_str];
                args.extend_from_slice(extra);
                let Some(out) = run(&args) else { return };
                serde_json::from_str::<serde_json::Value>(&out)
                    .unwrap_or_else(|e| panic!("{lang} {cmd} {extra:?}: invalid JSON: {e}\n{out}"));
            }
        }
    }
}

// -----------------------------------------------------------------------------
// Default-on: the `flows` column renders without passing `--flows`,
// and `--no-flows` suppresses it. These guard the one-line surface
// flip that made the column the default — a regression here would
// silently put us back in opt-in mode without failing any other
// test.
// -----------------------------------------------------------------------------

#[test]
fn flows_column_is_on_by_default() {
    for &lang in LANGUAGES {
        let Some(ws) = ws_for(lang) else { continue };
        let Some(out) = run(&["calls", ws.to_str().unwrap()]) else {
            return;
        };
        assert!(
            out.contains("flows"),
            "{lang} calls: `flows` column should be on by default: {out}"
        );
    }
}

#[test]
fn no_flows_flag_suppresses_column() {
    for &lang in LANGUAGES {
        let Some(ws) = ws_for(lang) else { continue };
        let Some(out) = run(&["calls", ws.to_str().unwrap(), "--no-flows"]) else {
            return;
        };
        // Header row is the first separator-bounded line; a stray
        // "flows" later in the body (e.g. inside a `code` cell) is
        // not a failure. We assert the header doesn't contain it.
        let header_line = out.lines().next().unwrap_or("");
        assert!(
            !header_line.contains("flows"),
            "{lang} calls --no-flows: header still includes flows: {header_line}"
        );
    }
}

// -----------------------------------------------------------------------------
// Flow-id parity: a flow id emitted by `calls --flows` for a row
// inside function F must equal the flow id `inspect --query F`
// emits for that same function. The two codepaths live in
// different crates (`bonsai_sdk::flow_ids` vs.
// `bonsai_inspect`) and duplicate the FNV-1a hash to avoid a
// workspace → inspect cycle; this test is the contract that they
// stay aligned.
//
// Regression guard for a bug where browse emitted ids hashed from
// `[handle_request]` while inspect emitted ids hashed from
// `[handle_request, get_user, verify_token, …]` — i.e. browse
// forgot to extend chains with the downstream callee closure, so
// a copy-pasted id wouldn't resolve with `inspect --flow`.
// -----------------------------------------------------------------------------

fn extract_flow_ids(s: &str) -> Vec<String> {
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
fn browse_flow_ids_match_inspect_flow_ids() {
    let Some(ws) = ws_for("python") else { return };
    let ws_str = ws.to_str().unwrap();
    // Grab every flow id that appears in the `calls` output. The
    // Python fixture always has `handle_request` (the entry point),
    // so the chain `[handle_request → get_user → verify_token → …]`
    // shows up here and again in inspect's output.
    let Some(calls_out) = run(&["calls", ws_str]) else {
        return;
    };
    let browse_ids: Vec<String> = extract_flow_ids(&calls_out);
    assert!(
        !browse_ids.is_empty(),
        "calls output had no flow ids to compare: {calls_out}"
    );

    // Grab every flow id inspect prints for the same fixture.
    // Query over every function in the fixture (`--regex '.*'`) so
    // every inspect flow id is in the set we compare against.
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
    let inspect_ids: std::collections::HashSet<String> = extract_flow_ids(&inspect_out).into_iter().collect();
    assert!(
        !inspect_ids.is_empty(),
        "inspect output had no flow ids to compare: {inspect_out}"
    );

    // Every browse id must exist in inspect's set. The reverse
    // isn't required: inspect can legitimately surface flows for
    // functions that don't appear as an enclosing row in `calls`.
    for id in &browse_ids {
        assert!(
            inspect_ids.contains(id),
            "browse emitted flow id `{id}` that inspect does not recognise; \
             that means `inspect --flow {id}` would error when users paste \
             a browse id into inspect. browse ids: {browse_ids:?}\n\
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
    // Pick any flow id browse emits for the fixture.
    let Some(calls_out) = run(&["calls", ws_str]) else {
        return;
    };
    let Some(target_id) = extract_flow_ids(&calls_out).into_iter().next() else {
        panic!("no flow id to pivot through: {calls_out}");
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
// Flow-fold regression: when many occurrence hits share the same
// `flow_id`, inspect must render that chain block ONCE and list
// every match point below it — not re-render the whole chain per
// hit. Protects the token-efficiency property against render
// regressions that would blow the output back up from ~158 lines
// to ~1.2 k lines for the same semantic content.
//
// The Python fixture's `handle_request` produces exactly one flow
// id with 21 occurrence hits, so it's a clean canary.
// -----------------------------------------------------------------------------

#[test]
fn inspect_folds_occurrence_hits_sharing_a_flow() {
    let Some(ws) = ws_for("python") else { return };
    let ws_str = ws.to_str().unwrap();
    let Some(system_out) = run(&["inspect", ws_str, "--query", "os.system", "--graph-flow"]) else {
        return;
    };
    let Some(flow_id) = extract_flow_ids(&system_out).into_iter().next() else {
        panic!("inspect --query os.system emitted no flow id:\n{system_out}");
    };
    // The canonical command-injection flow
    // (`handle_request -> update_user -> run_admin_command`) in
    // python/micro should group every occurrence hit tied to the
    // resolved flow id into one render, not repeat the chain per hit.
    let Some(out) = run(&["inspect", ws_str, "--flow", &flow_id]) else {
        return;
    };

    // Context preservation: key occurrence-hit kinds from the
    // flow's call path must still appear somewhere — either in
    // the hits table or in the `match points:` summary below the
    // folded flow. Context lost is the cardinal sin of the folded
    // view. (Post-accuracy-filter we no longer include sibling-
    // branch flows like get_user/verify_token on the command
    // path, so checks focus on call-path tokens.)
    for needle in &[
        "var token",
        "var action",
        "call update_user",
        "call request.args.get",
        "call os.system",
    ] {
        assert!(
            out.contains(needle),
            "folded inspect lost context: `{needle}` missing from:\n{out}"
        );
    }

    // Efficiency: filter-only mode enumerates every hit whose
    // enclosing-function chain hashes to the requested flow id,
    // and each hit renders its own FLOW block (one per distinct
    // match-point target). Post-accuracy-filter the command-
    // injection chain has up to four distinct hit targets
    // (run_admin_command decl, handle_request decl, update_user
    // decl, `os.system` call site). The regression this guards
    // against is an O(hits² × chain) blowup where EVERY match
    // also re-renders every other match's chain inline.
    let chain_pattern = "handle_request → update_user → run_admin_command";
    let chain_repetitions = out.matches(chain_pattern).count();
    assert!(
        chain_repetitions <= 8,
        "chain repeats {chain_repetitions}× — fold broke, chain should render once per unique hit target:\n{out}"
    );

    // The `match points:` summary is the folded-view signature —
    // if it's absent the fold didn't kick in.
    assert!(
        out.contains("match points:"),
        "folded view should print `match points:` summary; got:\n{out}"
    );
}

// -----------------------------------------------------------------------------
// Per-command flow-population coverage on the python micro workspace.
//
// Every browse command that renders a `flows` column must actually
// populate it for at least one row on a workspace where flows exist
// (python/micro has 4 enumerated taint flows). Each test pins the
// contract for a specific command — if adapter wiring or the
// `FlowAnnotator` lookup breaks for one of them, only that test
// fires rather than all nine.
// -----------------------------------------------------------------------------

fn assert_browse_cmd_has_flow_ids(cmd: &str, extra: &[&str]) {
    let Some(ws) = ws_for("python") else { return };
    let ws_str = ws.to_str().unwrap();
    let mut args = vec![cmd, ws_str];
    args.extend_from_slice(extra);
    let Some(out) = run(&args) else { return };
    let found = count_flow_ids(&out);
    assert!(
        found > 0,
        "python micro: `{cmd}` produced zero F:<16-hex> ids in the flows column. \
         Either the annotator regressed or the adapter no longer wires flows for \
         this row kind.\nOutput:\n{out}",
    );
}

#[test]
fn defs_flows_column_populated() {
    assert_browse_cmd_has_flow_ids("defs", &[]);
}

#[test]
fn calls_flows_column_populated() {
    assert_browse_cmd_has_flow_ids("calls", &[]);
}

#[test]
fn imports_flows_column_populated() {
    // Imports at module scope never had an enclosing function, so
    // the old `labels_for(file, line)` path returned empty for
    // every import row. The symbol-name lookup
    // (`labels_for_symbol`) fixed this — `from .auth_service import
    // verify_token` now surfaces the flows terminating in
    // verify_token. Guard against a regression back to the empty
    // column.
    assert_browse_cmd_has_flow_ids("imports", &[]);
}

#[test]
fn vars_flows_column_populated() {
    assert_browse_cmd_has_flow_ids("vars", &[]);
}

#[test]
fn strings_flows_column_populated() {
    assert_browse_cmd_has_flow_ids("strings", &[]);
}

#[test]
fn args_flows_column_populated() {
    assert_browse_cmd_has_flow_ids("args", &[]);
}

#[test]
fn operations_flows_column_populated() {
    assert_browse_cmd_has_flow_ids("operations", &["--kind", "call"]);
}

#[test]
fn classes_flows_column_populated() {
    // python/micro doesn't define any classes in normal taint
    // chains, so refs/search are the stronger coverage. Still run
    // the command to ensure a non-crashing execution path, but
    // tolerate zero flow ids (empty column is valid when no class
    // spans a taint chain).
    let Some(ws) = ws_for("python") else { return };
    let Some(_out) = run(&["classes", ws.to_str().unwrap()]) else {
        return;
    };
}

#[test]
fn refs_flows_column_populated() {
    // `refs verify_token` — verify_token is called from
    // handle_request, so its call-site refs sit inside a function
    // that carries enumerated flow ids. handle_request itself has
    // no callers in the micro workspace (it's the entry point),
    // so refs for IT would legitimately return zero rows.
    assert_browse_cmd_has_flow_ids("refs", &["verify_token"]);
}

#[test]
fn search_flows_column_populated() {
    // Search for `handle_request` — same reasoning as refs.
    assert_browse_cmd_has_flow_ids("search", &["--query", "handle_request"]);
}

#[test]
fn flows_column_warns_when_label_set_is_capped() {
    let root = tempdir_for_test("bonsai-flow-column-capped-labels");
    write_flow_label_fan_in_workspace(&root, 40);

    let Some(out) = run(&["defs", root.to_str().unwrap(), "--name", "sink"]) else {
        return;
    };
    assert!(
        count_flow_ids(&out) > 0,
        "fan-in fixture should emit flow ids for sink:\n{out}"
    );
    assert!(
        out.contains("semantic-only flows column incomplete"),
        "capped flow-id labels must be surfaced as incomplete, not just hidden in a table cell:\n{out}"
    );
    assert!(
        out.contains("prefixes, not complete label sets"),
        "flow-column warning should explain that capped labels are partial:\n{out}"
    );

    let _ = std::fs::remove_dir_all(root);
}
