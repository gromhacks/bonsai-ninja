//! Per-language interprocedural matrix — runs `interprocedural_taint`
//! on every supported-language micro fixture and verifies cross-module
//! propagation works end to end.
//!
//! The canonical micro fixture every language ships (under
//! `examples/<lang>/micro/`) has the shape:
//!
//! ```text
//!     handle_request / handleRequest / HandleRequest  (entry)
//!         └─ update_user / updateUser / UpdateUser  (mid)
//!                 └─ run_admin_command / runAdminCommand / RunAdminCommand (sink)
//! ```
//!
//! We seed **every parameter** of the mid-hop as tainted, run the
//! interprocedural pass, and assert the resulting `call_records`
//! include a propagation where the sink function is the callee. This
//! exercises the full resolver + alias + param-mapping machinery per
//! adapter.
//!
//! Fixtures live outside the crate, so we read them via a
//! `LanguageRegistry` wired with every adapter (mirroring the CLI
//! integration tests).

use bonsai_db::AnalyzerDb;
use bonsai_lang_api::LanguageRegistry;
use bonsai_taint::{call_site_receives_taint, interprocedural_taint, InterTaintConfig, TokenSet};
use bonsai_vfs::Vfs;
use std::sync::Arc;

/// One row of the test matrix: the language id, the mid-hop name
/// whose scope we seed, the sink name that must appear in the
/// propagation records, and the seed token names. Some languages
/// prefix variable references (PHP `$token`) — the seed carries both
/// forms so the matrix stays adapter-agnostic.
struct TaintRow {
    lang: &'static str,
    mid: &'static str,
    sink: &'static str,
    ws_subdir: &'static str,
    seed_names: &'static [&'static str],
}

fn matrix() -> Vec<TaintRow> {
    const COMMON: &[&str] = &["token", "action"];
    // PHP and Perl both use sigils on variable references.
    const SIGIL: &[&str] = &["token", "action", "$token", "$action"];
    // Erlang variables are capitalized by convention (`Token`, `Action`).
    const ERLANG: &[&str] = &["Token", "Action"];
    vec![
        TaintRow {
            lang: "c",
            mid: "update_user",
            sink: "run_admin_command",
            ws_subdir: "c/micro",
            seed_names: COMMON,
        },
        TaintRow {
            lang: "cpp",
            mid: "update_user",
            sink: "run_admin_command",
            ws_subdir: "cpp/micro",
            seed_names: COMMON,
        },
        TaintRow {
            lang: "csharp",
            mid: "UpdateUser",
            sink: "RunAdminCommand",
            ws_subdir: "csharp/micro",
            seed_names: COMMON,
        },
        TaintRow {
            lang: "go",
            mid: "UpdateUser",
            sink: "RunAdminCommand",
            ws_subdir: "go/micro",
            seed_names: COMMON,
        },
        TaintRow {
            lang: "java",
            mid: "updateUser",
            sink: "runAdminCommand",
            ws_subdir: "java/micro",
            seed_names: COMMON,
        },
        TaintRow {
            lang: "javascript",
            mid: "updateUser",
            sink: "runAdminCommand",
            ws_subdir: "javascript/micro",
            seed_names: COMMON,
        },
        TaintRow {
            lang: "kotlin",
            mid: "updateUser",
            sink: "runAdminCommand",
            ws_subdir: "kotlin/micro",
            seed_names: COMMON,
        },
        TaintRow {
            lang: "php",
            mid: "update_user",
            sink: "run_admin_command",
            ws_subdir: "php/micro",
            seed_names: SIGIL,
        },
        TaintRow {
            lang: "python",
            mid: "update_user",
            sink: "run_admin_command",
            ws_subdir: "python/micro",
            seed_names: COMMON,
        },
        TaintRow {
            lang: "ruby",
            mid: "update_user",
            sink: "run_admin_command",
            ws_subdir: "ruby/micro",
            seed_names: COMMON,
        },
        TaintRow {
            lang: "rust",
            mid: "update_user",
            sink: "run_admin_command",
            ws_subdir: "rust/micro",
            seed_names: COMMON,
        },
        TaintRow {
            lang: "scala",
            mid: "updateUser",
            sink: "runAdminCommand",
            ws_subdir: "scala/micro",
            seed_names: COMMON,
        },
        TaintRow {
            lang: "swift",
            mid: "updateUser",
            sink: "runAdminCommand",
            ws_subdir: "swift/micro",
            seed_names: COMMON,
        },
        TaintRow {
            lang: "typescript",
            mid: "updateUser",
            sink: "runAdminCommand",
            ws_subdir: "typescript/micro",
            seed_names: COMMON,
        },
        TaintRow {
            lang: "dart",
            mid: "updateUser",
            sink: "runAdminCommand",
            ws_subdir: "dart/micro",
            seed_names: COMMON,
        },
        TaintRow {
            lang: "objc",
            mid: "updateUser",
            sink: "runAdminCommand",
            ws_subdir: "objc/micro",
            seed_names: COMMON,
        },
        TaintRow {
            lang: "lua",
            mid: "updateUser",
            sink: "runAdminCommand",
            ws_subdir: "lua/micro",
            seed_names: COMMON,
        },
        TaintRow {
            lang: "elixir",
            mid: "update_user",
            sink: "run_admin_command",
            ws_subdir: "elixir/micro",
            seed_names: COMMON,
        },
        TaintRow {
            lang: "erlang",
            mid: "update_user",
            sink: "run_admin_command",
            ws_subdir: "erlang/micro",
            seed_names: ERLANG,
        },
        TaintRow {
            lang: "solidity",
            mid: "updateUser",
            sink: "runAdminCommand",
            ws_subdir: "solidity/micro",
            seed_names: COMMON,
        },
        TaintRow {
            lang: "perl",
            mid: "update_user",
            sink: "run_admin_command",
            ws_subdir: "perl/micro",
            seed_names: SIGIL,
        },
    ]
}

/// Path to the `examples/` directory, relative to the crate's
/// `CARGO_MANIFEST_DIR`.
fn examples_root() -> std::path::PathBuf {
    let manifest = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest.parent().unwrap().parent().unwrap().join("examples")
}

/// Open a workspace under `examples/<subdir>/` with every language
/// adapter registered.
fn open_fixture(subdir: &str) -> AnalyzerDb {
    let dir = examples_root().join(subdir);
    let vfs = Arc::new(Vfs::new());
    // Recursively ingest all files under the fixture.
    ingest_dir(&vfs, &dir, &dir);
    let registry = Arc::new(LanguageRegistry::new());
    registry.register(Arc::new(bonsai_lang_c::CAdapter::new()));
    registry.register(Arc::new(bonsai_lang_cpp::CppAdapter::new()));
    registry.register(Arc::new(bonsai_lang_csharp::CSharpAdapter::new()));
    registry.register(Arc::new(bonsai_lang_go::GoAdapter::new()));
    registry.register(Arc::new(bonsai_lang_java::JavaAdapter::new()));
    registry.register(Arc::new(bonsai_lang_javascript::JavaScriptAdapter::new()));
    registry.register(Arc::new(bonsai_lang_kotlin::KotlinAdapter::new()));
    registry.register(Arc::new(bonsai_lang_php::PhpAdapter::new()));
    registry.register(Arc::new(bonsai_lang_python::PythonAdapter::new()));
    registry.register(Arc::new(bonsai_lang_ruby::RubyAdapter::new()));
    registry.register(Arc::new(bonsai_lang_rust::RustAdapter::new()));
    registry.register(Arc::new(bonsai_lang_scala::ScalaAdapter::new()));
    registry.register(Arc::new(bonsai_lang_swift::SwiftAdapter::new()));
    registry.register(Arc::new(bonsai_lang_typescript::TypeScriptAdapter::new()));
    registry.register(Arc::new(bonsai_lang_dart::DartAdapter::new()));
    registry.register(Arc::new(bonsai_lang_objc::ObjCAdapter::new()));
    registry.register(Arc::new(bonsai_lang_lua::LuaAdapter::new()));
    registry.register(Arc::new(bonsai_lang_elixir::ElixirAdapter::new()));
    registry.register(Arc::new(bonsai_lang_erlang::ErlangAdapter::new()));
    registry.register(Arc::new(bonsai_lang_solidity::SolidityAdapter::new()));
    registry.register(Arc::new(bonsai_lang_perl::PerlAdapter::new()));
    let db = AnalyzerDb::new(vfs, registry);
    for file in db.vfs().all_files() {
        let _ = db.decl_index(file);
    }
    db
}

fn ingest_dir(vfs: &Arc<Vfs>, root: &std::path::Path, dir: &std::path::Path) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            ingest_dir(vfs, root, &path);
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        // Workspace-relative display path matches what the CLI
        // would produce.
        let display = path
            .strip_prefix(root.parent().unwrap_or(root))
            .unwrap_or(&path)
            .to_string_lossy()
            .to_string();
        vfs.write(display, Arc::<str>::from(text.as_str()));
    }
}

/// Look up the first `FuncId` matching `name` with Function / Method /
/// Constructor kind. Panics if not found — the tests assume the
/// canonical names exist in every micro fixture.
fn func_id(db: &AnalyzerDb, name: &str) -> bonsai_common::FuncId {
    let global = db.global_index();
    let mut matches = bonsai_resolve::resolve_callable(&global, name);
    assert!(
        !matches.is_empty(),
        "expected `{name}` decl in fixture, none found",
    );
    matches.remove(0)
}

fn seed_from_row(row: &TaintRow) -> TokenSet {
    row.seed_names.iter().map(|s| (*s).to_string()).collect()
}

fn call_spans(events: &[bonsai_lang_api::FlowEvent], out: &mut Vec<bonsai_common::Span>) {
    use bonsai_lang_api::FlowEvent;
    for event in events {
        match event {
            FlowEvent::Call { span, .. } => out.push(*span),
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                call_spans(then_events, out);
                call_spans(else_events, out);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                call_spans(body, out);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                call_spans(body, out);
                call_spans(catch_events, out);
                call_spans(finally_events, out);
            }
            _ => {}
        }
    }
}

fn dangerous_sink_call_needles(lang: &str) -> &'static [&'static str] {
    match lang {
        "c" | "cpp" | "objc" | "ruby" => &["system"],
        "csharp" => &["Process.Start"],
        "dart" => &["Process.runSync"],
        "elixir" => &["System.cmd"],
        "erlang" => &["os:cmd"],
        "go" => &["exec.Command"],
        "java" | "kotlin" => &["Runtime.getRuntime().exec"],
        "javascript" | "typescript" => &["execSync"],
        "lua" => &["os.execute"],
        "perl" => &["system"],
        "php" => &["exec"],
        "python" => &["os.system"],
        "rust" => &[".arg"],
        "scala" => &[".!"],
        // Solidity and Swift micro sinks are modeled through stateful
        // operation setup rather than a tainted direct call argument,
        // so the generic param-precision check below is not applicable.
        "solidity" | "swift" => &[],
        _ => &[],
    }
}

fn taint_config_for_lang(lang: &str) -> InterTaintConfig {
    let mut config = InterTaintConfig::default();
    if lang == "c" {
        // Mirrors the rulepack's explicit `sprintf` transfer:
        // formatted value args flow into the first, addressable output
        // buffer. Keeping this in config preserves engine purity while
        // making the C micro fixture exercise the real sink argument.
        config.output_arg_flows.push(bonsai_taint::OutputArgFlow {
            callee: "sprintf".to_string(),
            output_arg_index: 0,
            value_start_arg_index: Some(1),
            value_arg_indices: Vec::new(),
        });
    }
    config
}

fn matching_call_spans(
    events: &[bonsai_lang_api::FlowEvent],
    needles: &[&str],
    out: &mut Vec<bonsai_common::Span>,
) {
    use bonsai_lang_api::FlowEvent;
    for event in events {
        match event {
            FlowEvent::Call { name, span, .. } if needles.iter().any(|needle| name.contains(needle)) => {
                out.push(*span);
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                matching_call_spans(then_events, needles, out);
                matching_call_spans(else_events, needles, out);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                matching_call_spans(body, needles, out);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                matching_call_spans(body, needles, out);
                matching_call_spans(catch_events, needles, out);
                matching_call_spans(finally_events, needles, out);
            }
            _ => {}
        }
    }
}

fn dangerous_call_spans_for_lang(
    lang: &str,
    events: &[bonsai_lang_api::FlowEvent],
) -> Vec<bonsai_common::Span> {
    let needles = dangerous_sink_call_needles(lang);
    let mut spans = Vec::new();
    if !needles.is_empty() {
        matching_call_spans(events, needles, &mut spans);
    }
    spans
}

fn param_seed(param: &str) -> TokenSet {
    let mut out = TokenSet::default();
    out.insert(param.to_string());
    if let Some(stripped) = param.strip_prefix('$') {
        out.insert(stripped.to_string());
    } else {
        out.insert(format!("${param}"));
    }
    out
}

fn any_call_site_receives(
    db: &AnalyzerDb,
    func: bonsai_common::FuncId,
    spans: &[bonsai_common::Span],
    seeds: &TokenSet,
    config: &InterTaintConfig,
) -> bool {
    spans
        .iter()
        .any(|span| call_site_receives_taint(func, *span, seeds, config, db))
}

#[test]
fn interproc_propagates_mid_to_sink_for_every_language() {
    for row in matrix() {
        let db = open_fixture(row.ws_subdir);
        let mid = func_id(&db, row.mid);
        let sink = func_id(&db, row.sink);
        let seed = seed_from_row(&row);
        let result = interprocedural_taint(mid, &seed, &InterTaintConfig::default(), &db);
        // The sink should appear as a callee in at least one
        // propagation record somewhere downstream of mid.
        let propagated = result.call_records.iter().any(|record| record.callee == sink);
        assert!(
            propagated,
            "{}: interprocedural pass must produce a propagation record targeting `{}`; got {} records",
            row.lang,
            row.sink,
            result.call_records.len(),
        );
    }
}

#[test]
fn interproc_false_path_clean_seed_does_not_propagate() {
    // Running the interprocedural pass from `mid` with an EMPTY seed
    // produces no cross-function propagations — the engine shouldn't
    // invent taint out of nothing.
    for row in matrix() {
        let db = open_fixture(row.ws_subdir);
        let mid = func_id(&db, row.mid);
        let result = interprocedural_taint(mid, &TokenSet::default(), &InterTaintConfig::default(), &db);
        assert!(
            result.call_records.is_empty(),
            "{}: empty seed must produce zero propagation records; got {:?}",
            row.lang,
            result
                .call_records
                .iter()
                .map(|r| (r.caller, r.callee))
                .collect::<Vec<_>>(),
        );
    }
}

#[test]
fn sink_site_receives_tainted_param_for_every_language() {
    for row in matrix() {
        let db = open_fixture(row.ws_subdir);
        let sink = func_id(&db, row.sink);
        let global = db.global_index();
        let decl = global
            .decl_of(bonsai_common::SymbolId::new(sink.raw()))
            .unwrap_or_else(|| panic!("{}: missing sink decl `{}`", row.lang, row.sink));
        let mut spans = Vec::new();
        call_spans(&decl.flow_events, &mut spans);
        assert!(
            !spans.is_empty(),
            "{}: sink function `{}` has no call sites to validate",
            row.lang,
            row.sink
        );
        let mut seeds: TokenSet = decl.params.iter().cloned().collect();
        for param in &decl.params {
            if let Some(stripped) = param.strip_prefix('$') {
                seeds.insert(stripped.to_string());
            }
        }
        let config = taint_config_for_lang(row.lang);
        let any_sink_site_tainted = spans
            .iter()
            .any(|span| call_site_receives_taint(sink, *span, &seeds, &config, &db));
        assert!(
            any_sink_site_tainted,
            "{}: no call site inside `{}` receives any seeded sink parameter {:?}",
            row.lang, row.sink, decl.params
        );
    }
}

#[test]
fn sink_site_rejects_disjoint_seed_for_every_language() {
    for row in matrix() {
        let db = open_fixture(row.ws_subdir);
        let sink = func_id(&db, row.sink);
        let global = db.global_index();
        let decl = global
            .decl_of(bonsai_common::SymbolId::new(sink.raw()))
            .unwrap_or_else(|| panic!("{}: missing sink decl `{}`", row.lang, row.sink));
        let mut spans = Vec::new();
        call_spans(&decl.flow_events, &mut spans);
        assert!(
            !spans.is_empty(),
            "{}: sink function `{}` has no call sites to validate",
            row.lang,
            row.sink
        );
        let fake_seed: TokenSet = ["definitely_clean_unrelated_token"]
            .iter()
            .map(|s| (*s).to_string())
            .collect();
        let config = taint_config_for_lang(row.lang);
        assert!(
            !any_call_site_receives(&db, sink, &spans, &fake_seed, &config),
            "{}: unrelated seed must not taint any call site inside `{}`",
            row.lang,
            row.sink
        );
    }
}

#[test]
fn sink_site_param_mapping_is_precise_for_every_language_with_multiple_params() {
    for row in matrix() {
        if dangerous_sink_call_needles(row.lang).is_empty() {
            continue;
        }
        let db = open_fixture(row.ws_subdir);
        let sink = func_id(&db, row.sink);
        let global = db.global_index();
        let decl = global
            .decl_of(bonsai_common::SymbolId::new(sink.raw()))
            .unwrap_or_else(|| panic!("{}: missing sink decl `{}`", row.lang, row.sink));
        if decl.params.len() < 2 {
            continue;
        }
        let spans = dangerous_call_spans_for_lang(row.lang, &decl.flow_events);
        assert!(
            !spans.is_empty(),
            "{}: sink function `{}` has no dangerous call sites to validate",
            row.lang,
            row.sink
        );
        let config = taint_config_for_lang(row.lang);
        let mut tainting = Vec::new();
        let mut clean = Vec::new();
        for param in &decl.params {
            let seeds = param_seed(param);
            if any_call_site_receives(&db, sink, &spans, &seeds, &config) {
                tainting.push(param.clone());
            } else {
                clean.push(param.clone());
            }
        }
        assert!(
            !tainting.is_empty(),
            "{}: at least one sink param must taint a dangerous call in `{}`; params={:?}",
            row.lang,
            row.sink,
            decl.params
        );
        assert!(
            !clean.is_empty(),
            "{}: wrong/non-sink params must stay clean in `{}`; every param tainted a call site: {:?}",
            row.lang,
            row.sink,
            tainting
        );
    }
}

#[test]
fn interproc_token_side_does_not_taint_command_sink_for_every_language() {
    for row in matrix() {
        if dangerous_sink_call_needles(row.lang).is_empty() {
            continue;
        }
        let db = open_fixture(row.ws_subdir);
        let mid = func_id(&db, row.mid);
        let sink = func_id(&db, row.sink);
        let global = db.global_index();
        let sink_decl = global
            .decl_of(bonsai_common::SymbolId::new(sink.raw()))
            .unwrap_or_else(|| panic!("{}: missing sink decl `{}`", row.lang, row.sink));
        if sink_decl.params.len() < 2 {
            continue;
        }
        let spans = dangerous_call_spans_for_lang(row.lang, &sink_decl.flow_events);
        assert!(
            !spans.is_empty(),
            "{}: sink function `{}` has no dangerous call sites to validate",
            row.lang,
            row.sink
        );
        let token_seed = param_seed(row.seed_names[0]);
        let config = taint_config_for_lang(row.lang);
        let result = interprocedural_taint(mid, &token_seed, &config, &db);
        let mut checked_sink_state = false;
        for key in result.per_function.keys().filter(|key| key.func == sink) {
            checked_sink_state = true;
            let sink_seed: TokenSet = key.seed.iter().cloned().collect();
            assert!(
                !any_call_site_receives(&db, sink, &spans, &sink_seed, &config),
                "{}: token/auth-side seed {:?} reached dangerous command call in `{}` with sink seed {:?}",
                row.lang,
                token_seed,
                row.sink,
                sink_seed
            );
        }
        assert!(
            checked_sink_state || !result.call_records.iter().any(|record| record.callee == sink),
            "{}: propagation record reached `{}` but no sink state was available to validate",
            row.lang,
            row.sink
        );
    }
}
