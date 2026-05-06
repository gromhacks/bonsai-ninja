//! Security pipeline regressions for source-to-sink flows.
//!
//! These are not abstract `FlowEvent` unit tests. The small fixtures below
//! lock benchmark-shaped regressions, and the mega-flow matrix indexes the
//! checked-in examples for every supported adapter. Each row matches real
//! source and sink facts, then runs `run_taint_analysis` so source seeding,
//! matcher output, cross-function propagation, and finding construction are
//! exercised together.

use bonsai_lang_api::FlowEvent;
use bonsai_security::loader::LanguagePack;
use bonsai_security::rule::{ArgTaintedSpec, Severity, TaintSemantics};
use bonsai_security::{
    run_taint_analysis, ConstraintKind, MatchKind, MatchSpec, Rule, RuleConstraint, RuleKind, RuleTarget,
    Rulepack, TaintAnalysisOptions, TrustClass,
};
use bonsai_workspace::Workspace;
use std::{collections::BTreeSet, path::PathBuf, sync::Arc};

const ALL_LANGS: &[&str] = &[
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

/// Fixture suites that together cover taint-carrying graph shapes:
/// assignment chains, branch joins, callbacks, cross-file calls, receiver
/// state, sanitizer precision, exception regions, clean twins, and the
/// deep mixed-construct mega flow.
const TAINT_FIXTURE_SUITES: &[&str] = &[
    "assign_chain",
    "branch_merge",
    "callback_flow",
    "cross_file_chain",
    "receiver_type",
    "sanitizer_credit",
    "try_catch",
    "no_fp",
    "mega_flow",
];

/// The union of required `FlowEvent` variants the all-language mega-flow
/// fixtures currently exercise end-to-end through the adapter fact layer.
const REQUIRED_MEGA_FLOW_EVENT_UNION: &[&str] = &[
    "Assign", "Await", "Branch", "Call", "Continue", "Defer", "Loop", "Return", "Try", "Using", "Yield",
];

#[derive(Clone, Copy)]
struct Fixture {
    lang: &'static str,
    name: &'static str,
    files: &'static [(&'static str, &'static str)],
    sink_file_contains: &'static str,
}

fn workspace(files: &[(&str, &str)]) -> Workspace {
    let ws = Workspace::new(bonsai_adapters::all_languages_registry());
    for (path, src) in files {
        ws.vfs().write((*path).to_string(), Arc::<str>::from(*src));
    }
    for file in ws.vfs().all_files() {
        let _ = ws.db().decl_index(file);
        let _ = ws.db().import_index(file);
    }
    ws
}

fn repo_root() -> PathBuf {
    let mut p = std::env::current_dir().expect("cwd");
    p.push("../..");
    p.canonicalize().expect("repo root")
}

fn example_fixture_path(lang: &str, suite: &str) -> PathBuf {
    repo_root().join("examples").join(lang).join(suite)
}

fn fixture_has_source_files(path: &std::path::Path) -> bool {
    let Ok(entries) = std::fs::read_dir(path) else {
        return false;
    };
    entries.flatten().any(|entry| {
        let path = entry.path();
        if path.components().any(|c| c.as_os_str() == ".bonsai") {
            return false;
        }
        path.is_file() || (path.is_dir() && fixture_has_source_files(&path))
    })
}

fn index_real_fixture(lang: &str, suite: &str) -> Workspace {
    let root = example_fixture_path(lang, suite);
    Workspace::index(&root, bonsai_adapters::all_languages_registry())
        .unwrap_or_else(|err| panic!("{lang}/{suite}: index workspace failed: {err}"))
}

fn rules_root() -> PathBuf {
    repo_root().join("security-patterns")
}

fn required_mega_flow_event_kinds(lang: &str) -> &'static [&'static str] {
    match lang {
        "c" => &["Assign", "Branch", "Call", "Loop", "Return"],
        "cpp" => &["Assign", "Branch", "Call", "Loop", "Return", "Try"],
        "csharp" => &["Assign", "Await", "Branch", "Call", "Loop", "Return", "Using"],
        "dart" => &["Assign", "Await", "Branch", "Call", "Loop", "Return", "Try"],
        "elixir" => &["Assign", "Call"],
        "erlang" => &["Assign", "Branch", "Call", "Try", "Using"],
        "go" => &["Assign", "Branch", "Call", "Defer", "Loop", "Return"],
        "java" => &["Assign", "Branch", "Call", "Loop", "Return", "Try"],
        "javascript" => &["Assign", "Await", "Branch", "Call", "Loop", "Return", "Try"],
        "kotlin" => &["Assign", "Branch", "Call", "Return", "Try"],
        "lua" => &["Assign", "Branch", "Call", "Loop", "Return"],
        "objc" => &["Assign", "Branch", "Call", "Loop", "Return", "Try"],
        "perl" => &["Assign", "Branch", "Call", "Loop", "Return"],
        "php" => &["Assign", "Branch", "Call", "Loop", "Return", "Try"],
        "python" => &[
            "Assign", "Branch", "Call", "Loop", "Return", "Try", "Using", "Yield",
        ],
        "ruby" => &["Assign", "Call", "Continue", "Try", "Yield"],
        "rust" => &["Assign", "Branch", "Call", "Loop", "Return"],
        "scala" => &["Assign", "Branch", "Call"],
        "solidity" => &["Assign", "Branch", "Call", "Loop", "Return", "Try"],
        "swift" => &["Assign", "Branch", "Call", "Loop", "Return", "Try"],
        "typescript" => &["Assign", "Await", "Branch", "Call", "Loop", "Return", "Try"],
        _ => &[],
    }
}

fn collect_workspace_event_kinds(ws: &Workspace) -> BTreeSet<&'static str> {
    let mut kinds = BTreeSet::new();
    for file in ws.vfs().all_files() {
        if let Some(idx) = ws.db().decl_index(file) {
            for decl in &idx.defs {
                collect_event_kinds(&decl.flow_events, &mut kinds);
            }
        }
    }
    kinds
}

fn collect_event_kinds(events: &[FlowEvent], out: &mut BTreeSet<&'static str>) {
    for event in events {
        match event {
            FlowEvent::Call { .. } => {
                out.insert("Call");
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                out.insert("Branch");
                collect_event_kinds(then_events, out);
                collect_event_kinds(else_events, out);
            }
            FlowEvent::Loop { body, .. } => {
                out.insert("Loop");
                collect_event_kinds(body, out);
            }
            FlowEvent::Assign { .. } => {
                out.insert("Assign");
            }
            FlowEvent::Return { .. } => {
                out.insert("Return");
            }
            FlowEvent::Throw { .. } => {
                out.insert("Throw");
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                out.insert("Try");
                collect_event_kinds(body, out);
                collect_event_kinds(catch_events, out);
                collect_event_kinds(finally_events, out);
            }
            FlowEvent::Break { .. } => {
                out.insert("Break");
            }
            FlowEvent::Continue { .. } => {
                out.insert("Continue");
            }
            FlowEvent::Yield { .. } => {
                out.insert("Yield");
            }
            FlowEvent::Await { .. } => {
                out.insert("Await");
            }
            FlowEvent::Defer { body, .. } => {
                out.insert("Defer");
                collect_event_kinds(body, out);
            }
            FlowEvent::Using { body, .. } => {
                out.insert("Using");
                collect_event_kinds(body, out);
            }
            FlowEvent::Lifecycle { .. } => {
                out.insert("Lifecycle");
            }
        }
    }
}

fn rulepack(lang: &str, source_name: &str, sink_name: &str) -> Rulepack {
    let mut pack = Rulepack::default();
    pack.packs.insert(
        lang.to_string(),
        LanguagePack {
            language: lang.to_string(),
            sources: vec![rule(
                lang,
                RuleKind::Source,
                &format!("{lang}.test.source"),
                Some(TrustClass::Remote),
                None,
                source_name,
            )],
            sinks: vec![rule(
                lang,
                RuleKind::Sink,
                &format!("{lang}.test.sink"),
                None,
                Some(Severity::Critical),
                sink_name,
            )],
            sanitizers: Vec::new(),
        },
    );
    pack
}

fn return_sink_rulepack(lang: &str) -> Rulepack {
    let mut pack = Rulepack::default();
    let mut source = rule(
        lang,
        RuleKind::Source,
        &format!("{lang}.test.source"),
        Some(TrustClass::Remote),
        None,
        "source",
    );
    let sink = Rule {
        id: format!("{lang}.test.return_sink"),
        aliases: Vec::new(),
        enabled: true,
        disabled_reason: None,
        title: None,
        tag: Some("test-security-pipeline".to_string()),
        severity: Some(Severity::Critical),
        trust: None,
        category: Some("test".to_string()),
        cwe: Vec::new(),
        owasp: Vec::new(),
        frameworks: Vec::new(),
        packages: Vec::new(),
        imports: Vec::new(),
        modules: Vec::new(),
        manifests: Vec::new(),
        lockfiles: Vec::new(),
        payload_types: Vec::new(),
        match_spec: MatchSpec {
            kind: MatchKind::Return,
            callee: None,
            target: Some(RuleTarget {
                name: Some("return".to_string()),
                ..Default::default()
            }),
            search_depth: 0,
        },
        taint_semantics: None,
        constraints: RuleConstraint::default(),
        match_examples: Vec::new(),
        description: "return sink fixture".to_string(),
        kind: RuleKind::Sink,
        language: lang.to_string(),
        source_path: String::new(),
    };
    source.language = lang.to_string();
    pack.packs.insert(
        lang.to_string(),
        LanguagePack {
            language: lang.to_string(),
            sources: vec![source],
            sinks: vec![sink],
            sanitizers: Vec::new(),
        },
    );
    pack
}

fn c_recv_output_rulepack() -> Rulepack {
    let mut pack = Rulepack::default();
    let mut source = rule(
        "c",
        RuleKind::Source,
        "c.test.recv_output_source",
        Some(TrustClass::Remote),
        None,
        "recv",
    );
    source.taint_semantics = Some(TaintSemantics {
        clean_output_overwrite: None,
        source_output_args: vec![1],
        taint_receiver_from_args: false,
    });
    let mut sink = rule(
        "c",
        RuleKind::Sink,
        "c.test.dangerous_sink",
        None,
        Some(Severity::Critical),
        "dangerous",
    );
    sink.constraints = RuleConstraint(vec![ConstraintKind::ArgTainted {
        arg_tainted: ArgTaintedSpec {
            index: Some(0),
            kw: None,
        },
    }]);
    pack.packs.insert(
        "c".to_string(),
        LanguagePack {
            language: "c".to_string(),
            sources: vec![source],
            sinks: vec![sink],
            sanitizers: Vec::new(),
        },
    );
    pack
}

fn rule(
    lang: &str,
    kind: RuleKind,
    id: &str,
    trust: Option<TrustClass>,
    severity: Option<Severity>,
    callee: &str,
) -> Rule {
    Rule {
        id: id.to_string(),
        aliases: Vec::new(),
        enabled: true,
        disabled_reason: None,
        title: None,
        tag: Some("test-security-pipeline".to_string()),
        severity,
        trust,
        category: Some("test".to_string()),
        cwe: Vec::new(),
        owasp: Vec::new(),
        frameworks: Vec::new(),
        packages: Vec::new(),
        imports: Vec::new(),
        modules: Vec::new(),
        manifests: Vec::new(),
        lockfiles: Vec::new(),
        payload_types: Vec::new(),
        match_spec: MatchSpec {
            kind: MatchKind::Call,
            callee: Some(RuleTarget {
                name: Some(callee.to_string()),
                ..Default::default()
            }),
            target: None,
            search_depth: 0,
        },
        taint_semantics: None,
        constraints: RuleConstraint::default(),
        match_examples: Vec::new(),
        description: "source-to-sink security pipeline fixture".to_string(),
        kind,
        language: lang.to_string(),
        source_path: String::new(),
    }
}

fn assert_finding(fixture: Fixture) {
    assert_finding_with_options(fixture, TaintAnalysisOptions::default());
}

fn assert_finding_with_options(fixture: Fixture, options: TaintAnalysisOptions) {
    let ws = workspace(fixture.files);
    let pack = rulepack(fixture.lang, "source", "sink");
    let report = run_taint_analysis(&ws, &pack, options)
        .unwrap_or_else(|err| panic!("{} {}: taint analysis failed: {err}", fixture.lang, fixture.name));
    let matching: Vec<_> = report
        .findings
        .iter()
        .filter(|finding| finding.finding.sink.file.contains(fixture.sink_file_contains))
        .collect();
    assert!(
        !matching.is_empty(),
        "{} {}: expected a source-to-sink finding in `{}`; findings={:#?}",
        fixture.lang,
        fixture.name,
        fixture.sink_file_contains,
        report.findings
    );
    assert!(
        matching
            .iter()
            .any(|finding| matches!(finding.finding.precision.as_str(), "exact" | "narrowed")),
        "{} {}: supported source-to-sink flow must remain proven; matching findings={:#?}",
        fixture.lang,
        fixture.name,
        matching
    );
}

#[test]
fn c_output_arg_source_taints_only_declared_buffer_arg() {
    let ws = workspace(&[(
        "main.c",
        r#"
void dangerous(void *p);
int recv(int fd, void *buf, unsigned long len, int flags);

void handle(int fd) {
    char buf[128];
    recv(fd, buf, sizeof(buf), 0);
    dangerous(buf);
}
"#,
    )]);
    let report = run_taint_analysis(
        &ws,
        &c_recv_output_rulepack(),
        TaintAnalysisOptions {
            include_inferred_sources: false,
            ..Default::default()
        },
    )
    .expect("taint analysis");
    assert_eq!(report.findings.len(), 1, "{:#?}", report.findings);
}

#[test]
fn c_output_arg_source_does_not_taint_fd_or_size_args() {
    let ws = workspace(&[(
        "main.c",
        r#"
void dangerous(int p);
int recv(int fd, void *buf, unsigned long len, int flags);

void handle(int fd) {
    char buf[128];
    recv(fd, buf, sizeof(buf), 0);
    dangerous(fd);
}
"#,
    )]);
    let report = run_taint_analysis(
        &ws,
        &c_recv_output_rulepack(),
        TaintAnalysisOptions {
            include_inferred_sources: false,
            ..Default::default()
        },
    )
    .expect("taint analysis");
    assert!(report.findings.is_empty(), "{:#?}", report.findings);
}

#[test]
fn benchmark_shaped_security_flows_reach_sink() {
    for fixture in fixtures() {
        assert_finding(fixture);
    }
}

#[test]
fn benchmark_shaped_security_flows_resume_budget_chunks() {
    for fixture in fixtures() {
        assert_finding_with_options(
            fixture,
            TaintAnalysisOptions {
                interprocedural_budget: Some(1),
                ..Default::default()
            },
        );
    }
}

#[test]
fn taint_fixture_matrix_exists_for_every_supported_language() {
    let mut missing = Vec::new();
    for lang in ALL_LANGS {
        for suite in TAINT_FIXTURE_SUITES {
            let path = example_fixture_path(lang, suite);
            if !path.is_dir() || !fixture_has_source_files(&path) {
                missing.push(format!("{lang}/{suite}"));
            }
        }
    }

    assert!(
        missing.is_empty(),
        "every supported language must have every taint fixture suite; missing: {missing:#?}"
    );
}

#[test]
fn mega_flow_security_pipeline_covers_every_language_and_flow_event_kind() {
    let pack = bonsai_security::load_rulepack(&rules_root()).expect("rulepack loads");
    let mut union = BTreeSet::new();

    for lang in ALL_LANGS {
        let ws = index_real_fixture(lang, "mega_flow");

        let event_kinds = collect_workspace_event_kinds(&ws);
        union.extend(event_kinds.iter().copied());
        for required in required_mega_flow_event_kinds(lang) {
            assert!(
                event_kinds.contains(required),
                "{lang}: mega_flow fixture must export FlowEvent::{required}; got {event_kinds:?}"
            );
        }

        let report = run_taint_analysis(
            &ws,
            &pack,
            TaintAnalysisOptions {
                include_inferred_sources: true,
                ..Default::default()
            },
        )
        .unwrap_or_else(|err| panic!("{lang}: mega_flow taint analysis failed: {err}"));

        assert!(
            !report.findings.is_empty(),
            "{lang}: mega_flow must produce at least one source-to-sink finding"
        );
        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.finding.chain_display.len() >= 2),
            "{lang}: mega_flow must include at least one multi-hop source-to-sink chain; findings={:#?}",
            report.findings
        );
        assert!(
            report
                .findings
                .iter()
                .all(|finding| finding.finding.precision != "unknown"),
            "{lang}: taint precision must never silently degrade to unknown; findings={:#?}",
            report.findings
        );
    }

    for required in REQUIRED_MEGA_FLOW_EVENT_UNION {
        assert!(
            union.contains(required),
            "mega_flow matrix must cover FlowEvent::{required}; union={union:?}"
        );
    }
}

#[test]
fn tainted_inline_return_is_a_sink() {
    let ws = workspace(&[(
        "/app/page.ts",
        "function source(): string { return \"\"; }\n\n\
         export function page(): string {\n  const q = source();\n  return `<!doctype html><h1>${q}</h1>`;\n}\n",
    )]);
    let report = run_taint_analysis(
        &ws,
        &return_sink_rulepack("typescript"),
        TaintAnalysisOptions::default(),
    )
    .expect("taint analysis");
    assert!(
        report
            .findings
            .iter()
            .any(|finding| finding.finding.sink.file.contains("page.ts")
                && matches!(finding.finding.precision.as_str(), "exact" | "narrowed")),
        "expected tainted return sink finding, got {:#?}",
        report.findings
    );
}

fn fixtures() -> Vec<Fixture> {
    vec![
        Fixture {
            lang: "python",
            name: "cross_file_controller_to_service",
            sink_file_contains: "service.py",
            files: &[
                (
                    "/app/controller.py",
                    "from service import search\n\n\
                     def source():\n    return \"\"\n\n\
                     def handle():\n    q = source()\n    search(q)\n",
                ),
                (
                    "/app/service.py",
                    "def sink(value):\n    pass\n\n\
                     def search(term):\n    sink(term)\n",
                ),
            ],
        },
        Fixture {
            lang: "python",
            name: "return_then_sink",
            sink_file_contains: "app.py",
            files: &[(
                "/app/app.py",
                "def source():\n    return \"\"\n\n\
                 def sink(value):\n    pass\n\n\
                 def render(value):\n    return \"<p>\" + value + \"</p>\"\n\n\
                 def handle():\n    q = source()\n    body = render(q)\n    sink(body)\n",
            )],
        },
        Fixture {
            lang: "javascript",
            name: "destructured_shorthand_to_find",
            sink_file_contains: "service.js",
            files: &[
                (
                    "/app/controller.js",
                    "const svc = require('./service');\n\
                     function source() { return { email: 'a', password: 'b' }; }\n\
                     function handle() {\n  const { email, password } = source();\n  svc.search(email, password);\n}\n",
                ),
                (
                    "/app/service.js",
                    "function sink(filter) {}\n\
                     exports.search = function search(email, password) {\n  sink({ email, password });\n};\n",
                ),
            ],
        },
        Fixture {
            lang: "typescript",
            name: "cross_file_helper_template_sink",
            sink_file_contains: "render.ts",
            files: &[
                (
                    "/app/controller.ts",
                    "import { render } from './render';\n\
                     function source(): string { return ''; }\n\
                     export function handle(): void {\n  const q = source();\n  render(q);\n}\n",
                ),
                (
                    "/app/render.ts",
                    "function sink(value: string): void {}\n\
                     export function render(q: string): string {\n  const html = `<!doctype html><p>${q}</p>`;\n  sink(html);\n  return html;\n}\n",
                ),
            ],
        },
        Fixture {
            lang: "java",
            name: "controller_to_repository",
            sink_file_contains: "Repository.java",
            files: &[
                (
                    "/app/Controller.java",
                    "package app;\nclass Controller {\n  String source() { return \"\"; }\n  void handle() { Repository.search(source()); }\n}\n",
                ),
                (
                    "/app/Repository.java",
                    "package app;\nclass Repository {\n  static void sink(String value) {}\n  static void search(String sort) { sink(sort); }\n}\n",
                ),
            ],
        },
        Fixture {
            lang: "go",
            name: "cross_file_helper_sink",
            sink_file_contains: "sink.go",
            files: &[
                (
                    "/app/main.go",
                    "package main\nfunc source() string { return \"\" }\nfunc handle() { q := source(); render(q) }\n",
                ),
                (
                    "/app/sink.go",
                    "package main\nfunc sink(value string) {}\nfunc render(q string) { html := \"<p>\" + q + \"</p>\"; sink(html) }\n",
                ),
            ],
        },
    ]
}
