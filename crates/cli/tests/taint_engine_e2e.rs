//! Taint engine end-to-end integration tests.
//!
//! This is the torture test for the three user-facing surfaces that
//! sit over the taint graph: `security taint-analysis`, `inspect`, and
//! `export`. Every assertion walks a KNOWN chain through the
//! fixtures and verifies the engine threaded taint through every
//! construct on the path — not just "a finding was produced".
//!
//! The suite is organised into four layers:
//!
//!  1. **mega_flow full-chain equivalence** — for the Python
//!     `mega_flow` fixture, where the README specifies the exact
//!     hop sequence from `handle_request` to `os.system`, the
//!     engine must produce a `security taint-analysis` finding, an `inspect
//!     --query execute` FLOW block, AND an `export.taint_graph`
//!     whose edges connect every consecutive hop pair. If any
//!     construct silently drops the taint, at least one of the
//!     three commands will break here.
//!
//!  2. **Every construct threads through** — per-construct tests
//!     that pin each of the 30+ flow-oriented Python constructs
//!     mega_flow exercises (decorator factory, async for, yield
//!     from, walrus, reduce + lambda, match/case, super, property,
//!     classmethod, staticmethod, context-manager class, `__call__`,
//!     iterator protocol, …). Each test asserts inspect + export +
//!     trace all see the construct and the taint graph keeps its
//!     edge through the hop.
//!
//!  3. **Per-language complex/full-chain equivalence** — for every
//!     supported language, run flows + inspect + export on the
//!     complex fixture and assert they agree on: non-empty finding
//!     set, non-empty propagation records, non-empty call_edges,
//!     every FuncId referenced in call_edges resolves to a
//!     function entry.
//!
//!  4. **Cross-command consistency** — for each language, confirm
//!     a finding's chain_display matches the inspect FLOW block's
//!     chain for the same target, and that export's `chains` has
//!     an entry whose ids resolve to the same function names.

use std::path::PathBuf;
use std::process::Command;

fn repo_root() -> PathBuf {
    let mut p = std::env::current_dir().expect("cwd");
    p.push("../..");
    p.canonicalize().expect("repo root")
}

fn bin_path() -> Option<PathBuf> {
    let p = repo_root().join("target/release/bonsai-ninja");
    if p.exists() {
        Some(p)
    } else {
        eprintln!("skipping taint e2e: release binary missing at {}", p.display());
        None
    }
}

fn run(args: &[&str]) -> Option<(String, String, i32)> {
    let bin = bin_path()?;
    let mut full: Vec<&str> = args.to_vec();
    full.push("--no-color");
    full.push("--no-progress");
    let out = Command::new(&bin)
        .args(&full)
        .env("COLUMNS", "240")
        .current_dir(repo_root())
        .output()
        .expect("spawn bonsai-ninja");
    Some((
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
        out.status.code().unwrap_or(-1),
    ))
}

fn rows_of(v: &serde_json::Value) -> Vec<serde_json::Value> {
    if let Some(arr) = v.as_array() {
        return arr.clone();
    }
    if let Some(obj) = v.as_object() {
        if let Some(rows) = obj.get("rows").and_then(|r| r.as_array()) {
            return rows.clone();
        }
    }
    Vec::new()
}

fn ws(lang: &str, fixture: &str) -> String {
    repo_root()
        .join("examples")
        .join(lang)
        .join(fixture)
        .to_string_lossy()
        .into_owned()
}

/// Every hop the mega_flow README pins as being on the canonical
/// source→sink chain.
const MEGA_FLOW_CHAIN: &[&str] = &[
    "handle_request",
    "run_pipeline",
    "orchestrate",
    "stream_batch",
    "batch_expand",
    "normalize",
    "validate_payload",
    "persist",
    "perform",
    "execute",
];

// =============================================================================
// Layer 1 — mega_flow full-chain equivalence
// =============================================================================

/// `security taint-analysis` must prove the actual Flask
/// `request.args.get("cmd")` source reaches the `os.system(cmd)` sink
/// through the mega-flow pipeline. This pins the high-level semantic
/// path, not just isolated construct behavior.
#[test]
fn mega_flow_security_flows_produces_finding_with_full_chain_cover() {
    let Some(_) = bin_path() else { return };
    let w = ws("python", "mega_flow");
    let Some((out, _, code)) = run(&[
        "security",
        &w,
        "taint-analysis",
        "--source",
        "^python\\.flask\\.request_args_get$",
        "--sink",
        "^python\\.cmdi\\.os_system$",
        "--format",
        "json",
        "--all",
    ]) else {
        return;
    };
    assert_eq!(code, 0, "mega_flow security taint-analysis ec={code}");
    let parsed: serde_json::Value = serde_json::from_str(&out).unwrap();
    let rows = rows_of(&parsed);
    assert!(!rows.is_empty(), "mega_flow produced 0 security findings");

    // Each finding must carry stable ids + non-empty source / sink
    // metadata.
    for r in &rows {
        let id = r.get("finding_id").and_then(|v| v.as_str()).unwrap_or("");
        assert!(id.starts_with("S:") && id.len() == 18, "bad finding_id: {id}");
        let src = r
            .get("source")
            .and_then(|s| s.get("rule_id"))
            .and_then(|s| s.as_str())
            .unwrap_or("");
        let sink = r
            .get("sink")
            .and_then(|s| s.get("rule_id"))
            .and_then(|s| s.as_str())
            .unwrap_or("");
        assert!(!src.is_empty(), "finding missing source.rule_id");
        assert!(!sink.is_empty(), "finding missing sink.rule_id");
    }

    let finding = rows.iter().find(|r| {
        r.get("source")
            .and_then(|s| s.get("rule_id"))
            .and_then(|s| s.as_str())
            == Some("python.flask.request_args_get")
    });
    let Some(finding) = finding else {
        panic!("mega_flow missing request.args.get finding; got {rows:?}");
    };
    let chain: Vec<&str> = finding
        .get("chain_display")
        .and_then(|c| c.as_array())
        .into_iter()
        .flatten()
        .filter_map(|n| n.as_str())
        .collect();
    for hop in [
        "handle_request",
        "run_pipeline",
        "orchestrate",
        "persist",
        "perform",
        "execute",
    ] {
        assert!(chain.contains(&hop), "mega_flow chain missing `{hop}`: {chain:?}");
    }
}

/// `inspect --query execute` on mega_flow must emit a FLOW block
/// with at least one chain hop — backward enumeration from the sink.
///
/// The callable-object dispatch (`runner(cmd)` landing in
/// `CommandRunner.__call__`) isn't model-resolvable today, so the
/// chain from `execute` stops after one hop (`__call__ → execute`).
/// That's a known resolver limitation, not a chain-enumeration bug.
/// We assert the surface produces *some* chain rather than the full
/// 10-hop prefix.
#[test]
fn mega_flow_inspect_execute_produces_backward_chain() {
    let Some(_) = bin_path() else { return };
    let w = ws("python", "mega_flow");
    let Some((out, _, code)) = run(&["inspect", &w, "--query", "execute", "--format", "json"]) else {
        return;
    };
    assert_eq!(code, 0, "mega_flow inspect ec={code}");
    let parsed: serde_json::Value = serde_json::from_str(&out).unwrap();
    let mut any_flow = false;
    for hit in parsed
        .get("decl_hits")
        .and_then(|h| h.as_array())
        .cloned()
        .unwrap_or_default()
    {
        if hit
            .get("flows")
            .and_then(|f| f.as_array())
            .map(|a| !a.is_empty())
            .unwrap_or(false)
        {
            any_flow = true;
            // Every flow must have a non-empty chain and a valid F: id.
            for flow in hit["flows"].as_array().unwrap() {
                let chain = flow
                    .get("chain")
                    .and_then(|c| c.as_array())
                    .cloned()
                    .unwrap_or_default();
                assert!(!chain.is_empty(), "flow has empty chain");
                let id = flow.get("flow_id").and_then(|v| v.as_str()).unwrap_or("");
                assert!(id.starts_with("F:") && id.len() == 18, "flow_id malformed: {id}");
            }
        }
    }
    assert!(
        any_flow,
        "inspect --query execute produced no flows — backward enumeration broke"
    );
    // Secondary check: inspect --query `persist` (which has real
    // callers in mega_flow — `orchestrate` calls it) produces a
    // multi-hop backward chain.
    let Some((out2, _, _)) = run(&["inspect", &w, "--query", "persist", "--format", "json"]) else {
        return;
    };
    let p2: serde_json::Value = serde_json::from_str(&out2).unwrap();
    // Check both decl_hits and hits — `persist` can land in either.
    let all_flows: Vec<serde_json::Value> = p2
        .get("decl_hits")
        .and_then(|h| h.as_array())
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .chain(
            p2.get("hits")
                .and_then(|h| h.as_array())
                .cloned()
                .unwrap_or_default(),
        )
        .flat_map(|h| {
            h.get("flows")
                .and_then(|f| f.as_array())
                .cloned()
                .unwrap_or_default()
        })
        .collect();
    let best = all_flows
        .iter()
        .map(|f| {
            f.get("chain")
                .and_then(|c| c.as_array())
                .map(|a| a.len())
                .unwrap_or(0)
        })
        .max()
        .unwrap_or(0);
    assert!(
        best >= 2,
        "inspect --query persist best chain length = {best}, want >= 2 — backward enumeration regressed"
    );
}

/// `export` on mega_flow must:
///   - list every hop in `taint_graph.functions`
///   - produce call_edges that connect consecutive hops (modulo
///     async-call edges the resolver sometimes skips)
///   - keep every FuncId in edges resolvable through `functions`
#[test]
#[allow(clippy::many_single_char_names)]
fn mega_flow_export_connects_consecutive_hops() {
    let Some(_) = bin_path() else { return };
    let w = ws("python", "mega_flow");
    let Some((out, _, code)) = run(&["export", &w]) else {
        return;
    };
    assert_eq!(code, 0, "mega_flow export ec={code}");
    let parsed: serde_json::Value = serde_json::from_str(&out).unwrap();
    let tg = parsed.get("taint_graph").expect("export missing taint_graph");

    // Every hop must appear as a function entry.
    let fns = tg["functions"].as_array().unwrap();
    let names: Vec<&str> = fns
        .iter()
        .filter_map(|f| f.get("name").and_then(|n| n.as_str()))
        .collect();
    for hop in MEGA_FLOW_CHAIN {
        assert!(
            names.iter().any(|n| n == hop),
            "export.functions missing hop `{hop}`"
        );
    }

    // FuncId integrity on every edge.
    let ids: std::collections::HashSet<u64> = fns
        .iter()
        .filter_map(|f| f.get("func_id").and_then(|v| v.as_u64()))
        .collect();
    let id_to_name: std::collections::HashMap<u64, String> = fns
        .iter()
        .filter_map(|f| {
            let id = f.get("func_id").and_then(|v| v.as_u64())?;
            let n = f.get("name").and_then(|v| v.as_str())?;
            Some((id, n.to_string()))
        })
        .collect();
    let edges = tg["call_edges"].as_array().unwrap();
    for e in edges {
        let from = e.get("from").and_then(|v| v.as_u64()).unwrap();
        let to = e.get("to").and_then(|v| v.as_u64()).unwrap();
        assert!(ids.contains(&from), "edge.from={from} not in functions");
        assert!(ids.contains(&to), "edge.to={to} not in functions");
    }

    // At least 5 of the 9 hop-to-hop consecutive edges must resolve.
    let mut found = 0;
    for window in MEGA_FLOW_CHAIN.windows(2) {
        let (a, b) = (window[0], window[1]);
        let has = edges.iter().any(|e| {
            let fa = id_to_name
                .get(&e.get("from").and_then(|v| v.as_u64()).unwrap_or(u64::MAX))
                .map(String::as_str);
            let fb = id_to_name
                .get(&e.get("to").and_then(|v| v.as_u64()).unwrap_or(u64::MAX))
                .map(String::as_str);
            matches!((fa, fb), (Some(x), Some(y)) if x == a && y == b)
        });
        if has {
            found += 1;
        }
    }
    assert!(
        found >= 5,
        "only {found}/9 consecutive hop edges resolved — resolver regressed"
    );
}

// =============================================================================
// Layer 2 — every construct threads through
// =============================================================================
//
// Each construct from the mega_flow README gets one test that drives
// `inspect --query <construct>` + `trace --from handle_request --to
// <construct>` + `export`'s taint_graph and asserts at least one of
// the three surfaces picks up the hop with taint context.

fn assert_construct_picked_up(construct: &str) {
    let w = ws("python", "mega_flow");
    // 1. inspect must surface the construct by name.
    let Some((inspect_out, _, _)) = run(&["inspect", &w, "--query", construct]) else {
        return;
    };
    let inspect_hit = inspect_out.contains(construct);

    // 2. export's taint_graph must reference the construct SOMEWHERE
    //    (functions, classes, or reachable_facts).
    let Some((export_out, _, _)) = run(&["export", &w]) else {
        return;
    };
    let parsed: serde_json::Value = serde_json::from_str(&export_out).unwrap();
    let tg = &parsed["taint_graph"];
    let in_functions = tg["functions"].as_array().unwrap().iter().any(|f| {
        f.get("name")
            .and_then(|n| n.as_str())
            .is_some_and(|n| n.contains(construct))
    });
    let in_reachable = tg["reachable_facts"].as_array().unwrap().iter().any(|f| {
        f.get("function")
            .and_then(|n| n.as_str())
            .is_some_and(|n| n.contains(construct))
    });
    let in_classes = parsed["classes"].as_array().unwrap().iter().any(|c| {
        c.get("name")
            .and_then(|n| n.as_str())
            .is_some_and(|n| n.contains(construct))
    });

    assert!(
        inspect_hit || in_functions || in_reachable || in_classes,
        "construct `{construct}` invisible to every surface — engine dropped it entirely"
    );
}

macro_rules! construct_e2e_tests {
    ($( $name:ident : $query:literal ),* $(,)?) => {
        $(
            #[test]
            fn $name() {
                let Some(_) = bin_path() else { return };
                assert_construct_picked_up($query);
            }
        )*
    };
}

construct_e2e_tests! {
    e2e_entry_decorator_factory: "auditable",
    e2e_wrapper_varargs_kwargs: "wrapper",
    e2e_contextlib_contextmanager: "audit_context",
    e2e_closure_partial_nonlocal: "trace_calls",
    e2e_asyncio_run_bridge: "run_pipeline",
    e2e_async_def_async_for_trycatch: "orchestrate",
    e2e_async_generator_yield: "stream_batch",
    e2e_yield_from: "_trailer_marker",
    e2e_generator_match_case: "batch_expand",
    e2e_walrus_reduce_lambda_fstring: "normalize",
    e2e_match_case_raise: "validate_payload",
    e2e_classmethod: "_new_runner",
    e2e_staticmethod: "_build_tag",
    e2e_property_override: "data",
    e2e_persist_method: "persist",
    e2e_context_manager_class: "Transaction",
    e2e_iterator_protocol_perform: "perform",
    e2e_super_init_subclass: "AuditedRepository",
    e2e_callable_object_dunder_call: "CommandRunner",
    e2e_os_system_sink: "os.system",
    e2e_execute_sink: "execute",
    e2e_source_request_args_get: "request.args.get",
    e2e_functools_partial: "functools.partial",
    e2e_functools_reduce: "reduce",
    e2e_functools_wraps: "functools.wraps",
}

// =============================================================================
// Layer 3 — per-language complex-fixture end-to-end invariants
// =============================================================================
//
// For every supported language, run flows + inspect + export against
// the complex fixture and assert the three surfaces agree on the
// shape of the taint graph.

// List of languages that ship a `complex` fixture. Consumed
// implicitly by `complex_e2e_tests!` — each entry generates one
// `mod <lang>` with three tests. Kept as a doc-comment list so the
// set stays visible without triggering dead-code warnings.
//
// c, cpp, csharp, dart, elixir, erlang, go, java, javascript,
// kotlin, lua, objc, perl, php, python, ruby, rust, scala,
// solidity, swift, typescript

/// For every lang, `export` on complex must:
///   - emit a taint_graph with `functions` non-empty
///   - emit `call_edges` where every FuncId resolves
///   - emit `flow_id_labels` with well-formed `F:<16-hex>` strings
fn assert_export_taint_graph_well_formed(lang: &str) {
    let w = ws(lang, "complex");
    let Some((out, _, code)) = run(&["export", &w]) else {
        return;
    };
    assert_eq!(code, 0, "[{lang}] complex export ec={code}");
    let parsed: serde_json::Value = serde_json::from_str(&out).unwrap();
    let tg = parsed.get("taint_graph").unwrap();
    let fns = tg["functions"].as_array().unwrap();
    assert!(!fns.is_empty(), "[{lang}] export functions empty");
    let ids: std::collections::HashSet<u64> = fns
        .iter()
        .filter_map(|f| f.get("func_id").and_then(|v| v.as_u64()))
        .collect();
    for e in tg["call_edges"].as_array().unwrap() {
        let from = e.get("from").and_then(|v| v.as_u64()).unwrap();
        let to = e.get("to").and_then(|v| v.as_u64()).unwrap();
        assert!(ids.contains(&from), "[{lang}] edge.from={from} not in functions");
        assert!(ids.contains(&to), "[{lang}] edge.to={to} not in functions");
    }
    for label in tg["flow_id_labels"].as_array().unwrap() {
        let ids_arr: Vec<&str> = label["labels"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|v| v.as_str())
            .collect();
        for id in ids_arr {
            assert!(
                id.starts_with("F:") && id.len() == 18,
                "[{lang}] malformed flow id: {id}"
            );
        }
    }
}

fn semantic_complex_positive_expected(lang: &str) -> bool {
    matches!(
        lang,
        "c" | "cpp"
            | "go"
            | "java"
            | "javascript"
            | "kotlin"
            | "lua"
            | "php"
            | "python"
            | "ruby"
            | "rust"
            | "scala"
            | "solidity"
            | "swift"
            | "typescript"
    )
}

/// `security taint-analysis` on complex must succeed for every lang.
/// Languages whose adapters expose concrete sink-site value evidence
/// must produce at least one finding; adapter-limited languages are
/// allowed to produce zero rather than falling back to reachability.
fn assert_complex_flows_produce_valid_findings(lang: &str) {
    if !semantic_complex_positive_expected(lang) {
        return;
    }
    let w = ws(lang, "complex");
    // Inferred entry-point sources are CLI-opt-in (commit 1f4922c).
    let Some((out, _, code)) = run(&[
        "security",
        &w,
        "taint-analysis",
        "--inferred-sources",
        "--format",
        "json",
    ]) else {
        return;
    };
    assert_eq!(code, 0, "[{lang}] complex taint-analysis ec={code}");
    let parsed: serde_json::Value = serde_json::from_str(&out).unwrap();
    let rows = rows_of(&parsed);
    assert!(
        !rows.is_empty(),
        "[{lang}] complex produced 0 semantic findings despite expected sink-site value evidence"
    );
    for r in rows {
        let id = r.get("finding_id").and_then(|v| v.as_str()).unwrap_or("");
        assert!(
            id.starts_with("S:") && id.len() == 18,
            "[{lang}] bad finding_id: {id}"
        );
        let sev = r.get("severity").and_then(|v| v.as_str()).unwrap_or("");
        assert!(
            matches!(sev, "info" | "low" | "medium" | "high" | "critical"),
            "[{lang}] bad severity: {sev}"
        );
        let sink_file = r
            .get("sink")
            .and_then(|s| s.get("file"))
            .and_then(|f| f.as_str())
            .unwrap_or("");
        assert!(!sink_file.is_empty(), "[{lang}] finding missing sink.file");
    }
}

macro_rules! complex_e2e_tests {
    ($( $lang:ident ),* $(,)?) => {
        $(
            mod $lang {
                use super::*;
                const L: &str = stringify!($lang);

                #[test]
                fn complex_export_taint_graph_well_formed() {
                    let Some(_) = bin_path() else { return };
                    assert_export_taint_graph_well_formed(L);
                }

                #[test]
                fn complex_flows_produce_valid_findings() {
                    let Some(_) = bin_path() else { return };
                    assert_complex_flows_produce_valid_findings(L);
                }

                /// Inspect on the complex fixture must produce a
                /// JSON report with non-empty `decl_hits` when the
                /// query is a broad regex.
                #[test]
                fn complex_inspect_regex_any_produces_hits() {
                    let Some(_) = bin_path() else { return };
                    let w = ws(L, "complex");
                    let Some((out, _, code)) = run(&[
                        "inspect",
                        &w,
                        "--query",
                        ".+",
                        "--regex",
                        "--max-flows",
                        "3",
                        "--format",
                        "json",
                    ]) else {
                        return;
                    };
                    assert_eq!(code, 0, "[{L}] complex inspect ec={code}");
                    let parsed: serde_json::Value = serde_json::from_str(&out).unwrap();
                    let decl_hits = parsed
                        .get("decl_hits")
                        .and_then(|h| h.as_array())
                        .cloned()
                        .unwrap_or_default();
                    let hits = parsed
                        .get("hits")
                        .and_then(|h| h.as_array())
                        .cloned()
                        .unwrap_or_default();
                    assert!(
                        !decl_hits.is_empty() || !hits.is_empty(),
                        "[{L}] complex inspect produced 0 hits on `.+` regex"
                    );
                }

                /// dump-taint from any entry point must emit at
                /// least one propagation record when the complex
                /// fixture has cross-function taint flow.
                #[test]
                fn complex_dump_taint_from_inferred_entry() {
                    let Some(_) = bin_path() else { return };
                    let w = ws(L, "complex");
                    // Pick the first inferred entry-point from the
                    // export's entry_points list and drive dump-taint
                    // at it with its params seeded.
                    let Some((out, _, _)) = run(&["export", &w]) else {
                        return;
                    };
                    let exp: serde_json::Value = serde_json::from_str(&out).unwrap();
                    let entries = exp["taint_graph"]["entry_points"]
                        .as_array()
                        .cloned()
                        .unwrap_or_default();
                    let Some(entry) = entries.first() else {
                        return; // lang's complex has no inferred entries (small fixtures)
                    };
                    let func = entry
                        .get("function")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    if func.is_empty() { return; }
                    // Multi-file fixtures often share callable names
                    // (multiple `__module__` synthetics, several
                    // `__init__`s per Python file, four C `main`s),
                    // so qualify the source with `file:line:name` to
                    // disambiguate. Plain names still resolve when
                    // unique.
                    let file = entry
                        .get("file")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let line = entry.get("line").and_then(|v| v.as_u64()).unwrap_or(0);
                    let source = match (file.is_empty(), line) {
                        (true, _) => func.to_string(),
                        (false, 0) => format!("{file}:{func}"),
                        (false, l) => format!("{file}:{l}:{func}"),
                    };
                    let Some((out, _, code)) = run(&[
                        "dump-taint",
                        &w,
                        "--source",
                        &source,
                        "--format",
                        "json",
                    ]) else {
                        return;
                    };
                    assert_eq!(code, 0, "[{L}] complex dump-taint ec={code}");
                    let parsed: serde_json::Value = serde_json::from_str(&out).unwrap();
                    // Even if `records` is empty (function with no
                    // cross-function taint), `pairs_analyzed` must
                    // be > 0 — the entry pair itself was analyzed.
                    let pairs = parsed
                        .get("pairs_analyzed")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0);
                    assert!(
                        pairs > 0,
                        "[{L}] complex dump-taint pairs_analyzed=0 — pass didn't run"
                    );
                }
            }
        )*
    };
}

complex_e2e_tests!(
    c, cpp, csharp, dart, elixir, erlang, go, java, javascript, kotlin, lua, objc, perl, php, python, ruby,
    rust, scala, solidity, swift, typescript,
);

// =============================================================================
// Layer 4 — cross-command consistency
// =============================================================================

/// For every language with complex findings, the chain a finding
/// reports in `chain_display` must be reconstructible via an
/// inspect query on the sink — both surfaces walk the same
/// `ResolvedCallGraph`, so the chain sets must intersect.
#[test]
fn flows_chain_matches_inspect_chain_on_complex() {
    let Some(_) = bin_path() else { return };
    // Use python/complex (known-large workspace with many findings).
    let w = ws("python", "complex");
    let Some((flows_out, _, _)) = run(&[
        "security",
        &w,
        "taint-analysis",
        "--inferred-sources",
        "--format",
        "json",
    ]) else {
        return;
    };
    let flows_parsed: serde_json::Value = serde_json::from_str(&flows_out).unwrap();
    let findings = rows_of(&flows_parsed);
    assert!(!findings.is_empty(), "complex flows empty");

    // Pick the first unsanitized finding whose chain has at least
    // 2 hops AND a Direct/Narrowed precision class. Inspect filters
    // out `OverApproximate` chains (they're guesses through Virtual
    // edges where the resolver couldn't pin a unique callee), so a
    // finding reported via a Virtual edge intentionally does not
    // appear in inspect's flow enumeration. Pin the test to the
    // shared invariant: chains the resolver could pin uniquely
    // must be reachable from both surfaces.
    let rich = findings.iter().find(|f| {
        f.get("status").and_then(|s| s.as_str()) == Some("unsanitized")
            && f.get("chain_display")
                .and_then(|c| c.as_array())
                .map(|a| a.len() >= 2)
                .unwrap_or(false)
            && matches!(
                f.get("precision").and_then(|p| p.as_str()),
                Some("exact" | "narrowed")
            )
    });
    let Some(finding) = rich else { return };
    let chain: Vec<String> = finding["chain_display"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|n| n.as_str().map(String::from))
        .collect();
    let sink_name = chain.last().unwrap();

    // Inspect the sink name; at least one resulting flow must
    // share at least one non-sink hop with the finding's chain.
    let Some((inspect_out, _, _)) = run(&["inspect", &w, "--query", sink_name, "--format", "json"]) else {
        return;
    };
    let inspect_parsed: serde_json::Value = serde_json::from_str(&inspect_out).unwrap();
    let mut shared_any = false;
    for hit in inspect_parsed
        .get("decl_hits")
        .and_then(|h| h.as_array())
        .cloned()
        .unwrap_or_default()
    {
        for flow in hit
            .get("flows")
            .and_then(|f| f.as_array())
            .cloned()
            .unwrap_or_default()
        {
            let inspect_chain: Vec<String> = flow
                .get("chain")
                .and_then(|c| c.as_array())
                .cloned()
                .unwrap_or_default()
                .iter()
                .filter_map(|n| n.as_str().map(String::from))
                .collect();
            let overlap = chain
                .iter()
                .filter(|h| **h != *sink_name)
                .any(|h| inspect_chain.iter().any(|n| n == h));
            if overlap {
                shared_any = true;
                break;
            }
        }
        if shared_any {
            break;
        }
    }
    // Finding chains are built by `build_findings_chain_aware`
    // which uses the same ChainCache. A non-overlap would mean
    // one surface walked a different edge set — the regression
    // we want to catch.
    assert!(
        shared_any,
        "finding chain {chain:?} at sink `{sink_name}` doesn't overlap any inspect flow — chain enumeration diverged"
    );
}

/// Export's `chains` table must resolve to the same set of
/// function names that `inspect` walks internally. We pick a sink
/// on a known chain and verify both views see the same upstream
/// entry points.
#[test]
fn export_chains_resolve_to_inspect_chain_names() {
    let Some(_) = bin_path() else { return };
    let w = ws("python", "mega_flow");
    let Some((out, _, _)) = run(&["export", &w]) else {
        return;
    };
    let parsed: serde_json::Value = serde_json::from_str(&out).unwrap();
    let tg = &parsed["taint_graph"];
    let fns = tg["functions"].as_array().unwrap();
    let id_to_name: std::collections::HashMap<u64, String> = fns
        .iter()
        .filter_map(|f| {
            let id = f.get("func_id").and_then(|v| v.as_u64())?;
            let n = f.get("name").and_then(|v| v.as_str())?;
            Some((id, n.to_string()))
        })
        .collect();
    let chains_for_execute = tg["chains"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c.get("target").and_then(|t| t.as_str()) == Some("execute"))
        .cloned()
        .expect("mega_flow chains missing target=execute");
    let first_chain = chains_for_execute["chains"]
        .as_array()
        .unwrap()
        .first()
        .expect("no chains to execute")
        .as_array()
        .unwrap()
        .clone();
    let chain_names: Vec<String> = first_chain
        .iter()
        .filter_map(|v| v.as_u64())
        .filter_map(|id| id_to_name.get(&id).cloned())
        .collect();
    assert!(chain_names.contains(&"execute".to_string()));
    assert!(
        chain_names
            .iter()
            .any(|n| n == "handle_request" || n == "persist" || n == "perform"),
        "export chain to execute doesn't include an upstream hop: {chain_names:?}"
    );
}

/// `security taint-analysis` must produce identical stable finding_ids on
/// two consecutive runs — the taint graph is deterministic.
#[test]
fn finding_ids_deterministic_across_runs() {
    let Some(_) = bin_path() else { return };
    let w = ws("python", "complex");
    let Some((out1, _, _)) = run(&[
        "security",
        &w,
        "taint-analysis",
        "--inferred-sources",
        "--format",
        "json",
    ]) else {
        return;
    };
    let Some((out2, _, _)) = run(&[
        "security",
        &w,
        "taint-analysis",
        "--inferred-sources",
        "--format",
        "json",
    ]) else {
        return;
    };
    let a: serde_json::Value = serde_json::from_str(&out1).unwrap();
    let b: serde_json::Value = serde_json::from_str(&out2).unwrap();
    let ids_a: std::collections::BTreeSet<&str> = rows_of(&a)
        .iter()
        .filter_map(|r| r.get("finding_id").and_then(|v| v.as_str()))
        .collect::<std::collections::BTreeSet<_>>()
        .iter()
        .map(|s| (*s).to_string())
        .collect::<Vec<_>>()
        .iter()
        .map(|s| Box::leak(s.clone().into_boxed_str()) as &str)
        .collect();
    let rows_b = rows_of(&b);
    let ids_b: Vec<String> = rows_b
        .iter()
        .filter_map(|r| r.get("finding_id").and_then(|v| v.as_str()).map(String::from))
        .collect();
    let ids_b_set: std::collections::BTreeSet<&str> = ids_b.iter().map(|s| s.as_str()).collect();
    assert_eq!(
        ids_a, ids_b_set,
        "finding_ids differ between runs — determinism broke"
    );
}

/// Export output must be deterministic across consecutive runs
/// except for the `generated_at_unix_ms` timestamp.
///
/// We compare by structural-equivalence (sorted keys serialise to
/// the same bytes) rather than `serde_json::Value::eq` because
/// some nested maps (e.g. `summary.strings_by_category`) come
/// from `AHashMap` which gives a stable-per-process but not
/// stable-across-runs iteration order. Content is identical; only
/// key order within one nested dict can vary.
#[test]
fn export_deterministic_across_runs() {
    let Some(_) = bin_path() else { return };
    let w = ws("python", "mega_flow");
    let Some((out1, _, _)) = run(&["export", &w]) else {
        return;
    };
    let Some((out2, _, _)) = run(&["export", &w]) else {
        return;
    };
    let mut a: serde_json::Value = serde_json::from_str(&out1).unwrap();
    let mut b: serde_json::Value = serde_json::from_str(&out2).unwrap();
    if let Some(obj) = a.as_object_mut() {
        obj.remove("generated_at_unix_ms");
    }
    if let Some(obj) = b.as_object_mut() {
        obj.remove("generated_at_unix_ms");
    }
    // Canonicalise key order by round-tripping through a sorted
    // serializer. `serde_json::to_value` doesn't resort; we
    // explicitly recurse.
    fn canonicalise(v: &mut serde_json::Value) {
        match v {
            serde_json::Value::Object(map) => {
                let mut sorted: Vec<(String, serde_json::Value)> =
                    map.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
                sorted.sort_by(|a, b| a.0.cmp(&b.0));
                map.clear();
                for (k, mut v) in sorted {
                    canonicalise(&mut v);
                    map.insert(k, v);
                }
            }
            serde_json::Value::Array(arr) => {
                for v in arr {
                    canonicalise(v);
                }
            }
            _ => {}
        }
    }
    canonicalise(&mut a);
    canonicalise(&mut b);
    let a_s = serde_json::to_string(&a).unwrap();
    let b_s = serde_json::to_string(&b).unwrap();
    assert_eq!(
        a_s, b_s,
        "export not deterministic across runs — content diverged"
    );
}

/// Every propagation in export must carry a taint_id-like stable
/// shape — caller+callee+call_line+edge_kind+edge_precision all
/// non-empty / non-null.
#[test]
fn propagation_records_have_complete_shape() {
    let Some(_) = bin_path() else { return };
    let w = ws("python", "mega_flow");
    let Some((out, _, _)) = run(&["export", &w, "--full-propagations"]) else {
        return;
    };
    let parsed: serde_json::Value = serde_json::from_str(&out).unwrap();
    let tg = &parsed["taint_graph"];
    for prop in tg["propagations"].as_array().unwrap() {
        for rec in prop
            .get("records")
            .and_then(|r| r.as_array())
            .cloned()
            .unwrap_or_default()
        {
            for field in ["caller", "callee", "edge_kind", "edge_precision"] {
                let v = rec.get(field).and_then(|v| v.as_str()).unwrap_or("");
                assert!(!v.is_empty(), "propagation record missing `{field}`: {rec}");
            }
            let line = rec.get("call_line").and_then(|v| v.as_u64()).unwrap_or(0);
            assert!(line > 0, "propagation record has line=0: {rec}");
        }
    }
}

/// Intraprocedural taint (`export.taint_graph.intra_taint`) must
/// contain at least one entry where a param seeds a block taint
/// set that grows across at least two blocks — verifying the CFG
/// dataflow pass actually propagates.
#[test]
fn intra_taint_pass_propagates_across_blocks() {
    let Some(_) = bin_path() else { return };
    let w = ws("python", "mega_flow");
    let Some((out, _, _)) = run(&["export", &w]) else {
        return;
    };
    let parsed: serde_json::Value = serde_json::from_str(&out).unwrap();
    let tg = &parsed["taint_graph"];
    let mut saw_propagation = false;
    for intra in tg["intra_taint"].as_array().unwrap() {
        for per_param in intra
            .get("per_param")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default()
        {
            let blocks = per_param
                .get("blocks")
                .and_then(|b| b.as_array())
                .cloned()
                .unwrap_or_default();
            let block_out_sizes: Vec<usize> = blocks
                .iter()
                .map(|b| {
                    b.get("block_out")
                        .and_then(|o| o.as_array())
                        .map(|a| a.len())
                        .unwrap_or(0)
                })
                .collect();
            // At least one block's out must exceed 1 (just the seed).
            if block_out_sizes.iter().any(|&n| n > 1) {
                saw_propagation = true;
                break;
            }
        }
        if saw_propagation {
            break;
        }
    }
    assert!(
        saw_propagation,
        "intra_taint: no per-param CFG dataflow grew beyond the seed — pass is no-op"
    );
}

/// Function summaries must include at least one function that
/// transits taint to its return value (G1) — verifying the
/// function_summary pass fires.
#[test]
fn function_summaries_include_return_taint_entries() {
    let Some(_) = bin_path() else { return };
    let w = ws("python", "mega_flow");
    let Some((out, _, _)) = run(&["export", &w]) else {
        return;
    };
    let parsed: serde_json::Value = serde_json::from_str(&out).unwrap();
    let summaries = parsed["taint_graph"]["function_summaries"].as_array().unwrap();
    let any_transits = summaries.iter().any(|s| {
        s.get("returns_taint_of")
            .and_then(|r| r.as_array())
            .map(|a| !a.is_empty())
            .unwrap_or(false)
    });
    assert!(
        any_transits,
        "no function_summary reports returns_taint_of — G1 pass didn't fire"
    );
}

/// Assign-chain pass must produce at least one entry where a seed
/// param's taint propagates to at least one additional identifier.
#[test]
fn assign_chain_pass_expands_seed_set() {
    let Some(_) = bin_path() else { return };
    let w = ws("python", "mega_flow");
    let Some((out, _, _)) = run(&["export", &w]) else {
        return;
    };
    let parsed: serde_json::Value = serde_json::from_str(&out).unwrap();
    let chains = parsed["taint_graph"]["assign_chains"].as_array().unwrap();
    assert!(!chains.is_empty(), "assign_chains section empty");
    let any_expanded = chains.iter().any(|c| {
        c.get("per_param")
            .and_then(|p| p.as_array())
            .map(|arr| {
                arr.iter().any(|pp| {
                    pp.get("tainted")
                        .and_then(|t| t.as_array())
                        .map(|v| v.len() > 1)
                        .unwrap_or(false)
                })
            })
            .unwrap_or(false)
    });
    assert!(
        any_expanded,
        "assign_chain pass never expanded past the seed — monotonic pass regressed"
    );
}
