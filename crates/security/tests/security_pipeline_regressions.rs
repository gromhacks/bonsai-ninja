//! Security pipeline regressions for source-to-sink flows.
//!
//! These are not abstract `FlowEvent` unit tests. The small fixtures below
//! lock benchmark-shaped regressions, and the mega-flow matrix indexes the
//! checked-in examples for every supported adapter. Each row matches real
//! source and sink facts, then runs `run_taint_analysis` so source seeding,
//! matcher output, cross-function propagation, and finding construction are
//! exercised together.

use bonsai_idg::PointKind;
use bonsai_lang_api::{FlowEvent, StaticScalarValue};
use bonsai_security::loader::LanguagePack;
use bonsai_security::rule::{ArgTaintedSpec, Severity, TaintSemantics};
use bonsai_security::{
    run_taint_analysis, run_taint_analysis_with_phase_progress, AnalysisSemantics,
    CharacterConstraintSemantics, ConfiguredArgumentReceiverGuardSemantics,
    ConfiguredCallArgumentGuardSemantics, ConstraintKind, DynamicKeyDenylistGuardSemantics, FindingStatus,
    FlowClass, GuardProfile, MatchKind, MatchSpec, NoSqlFilterSemantics, PathContainmentGuardSemantics,
    ReceiverConfigurationGuardSemantics, ReceiverFactoryGuardSemantics,
    RelativePathContainmentGuardSemantics, RequiredAggregateFieldSemantics, RequiredCallArgumentSemantics,
    RequiredNamedArgumentSemantics, RequiredReceiverCallSemantics, Rule, RuleConstraint, RuleKind,
    RuleTarget, Rulepack, SourceAnalysisOptions, SourceLineageLimits, TaintAnalysisOptions, TrustClass,
    UrlComponentSemantics, UrlDnsGuardSemantics, UrlGuardRootSemantics, UrlHostAllowlistSemantics,
    UrlNetworkGuardSemantics, UrlReconstructionGuardSemantics, UrlRedirectGuardSemantics,
    UrlSchemeGuardSemantics,
};
use bonsai_taint::{compose_idg_seed_nodes, ensure_idg_service, IdgSeedRequest, TokenSet};
use bonsai_workspace::Workspace;
use std::{
    collections::BTreeSet,
    fmt::Write as _,
    path::PathBuf,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

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

fn expected_mega_flow_findings_with_inferred_sources(lang: &str) -> usize {
    match lang {
        "c" => 1,
        // argv → env.cmd → … → repo.cmd() → std::system: a real CWE-78
        // command-injection threaded through the C++ pipeline. The
        // tainted `.cmd` field is what reaches the sink.
        "cpp" => 1,
        // Console.ReadLine → Envelope.Cmd → Pipeline.Orchestrate (record `with`)
        // → Storage.Persist → AuditedRepository.Run → base.Run →
        // Repository.Run → Cmd property getter (expression-bodied
        // `Cmd => Data.Cmd`) → Executor.Execute → Process.Start: a real
        // CWE-78 command-injection threaded through C#'s full FN-language
        // construct stack (records, properties, inheritance, ctor chains,
        // async). Unblocked 2026-05-27 by the lang_csharp synthesis
        // additions (expression-bodied-property getter modeled as
        // `Call+Return` member-access with receiver_types, qualified bare
        // property reads emitting an explicit `Call` event for
        // walk_call's args-empty recv-slot fallback, and constructor
        // implicit-Return synthesis so the ctor chain forwards param taint
        // to the caller's allocation).
        "csharp" => 1,
        // stdin.readLineSync → Envelope.cmd → pipeline.orchestrate
        // (record copyWith) → storage.persist → AuditedRepository.run
        // → super.run → Repository.run → cmd getter (expression-bodied
        // `String get cmd => data.cmd`) → execute → Process.runSync
        // (runInShell): a real CWE-78 command-injection through Dart's
        // full FN-language construct stack (mixins, super-init params,
        // getters, factory ctors, async streams). Unblocked 2026-05-27
        // by the lang_dart synthesis additions (member-access getter
        // modeled as `Call+Return`, bare getter reads qualified with
        // explicit `Call` for walk_call's recv-slot fallback, ctor
        // One finding: the readLineSync → Process.runSync command
        // injection. The flow is reachable via two entry chains
        // (`handle_request → …` directly and `__module__ → handle_request
        // → …`) but both share the same source, sink, `finding_id`, and
        // `group_id` — so the combiner reports them as one finding, not
        // two duplicate rows (combiner keys on `group_id`, not chain).
        "dart" => 1,
        // System.argv → envelope.cmd → … → :os.cmd: a real CWE-78
        // command-injection threaded through the Elixir pipeline.
        "elixir" => 1,
        // io:get_line → envelope.cmd → ... → os:cmd. The source is
        // reachable through two equivalent inferred/member paths, but
        // they share one group_id and the report combiner emits a single
        // combined finding with both member ids.
        "erlang" => 1,
        "go" => 1,
        // NOTE: java is the validated record-synthesis case. C# uses the
        // same shared helper but stays FN — its remaining blocker is the
        // bare implicit-`this` property read `var c = Cmd;` in
        // `Repository.Run` (expression-bodied `Cmd => Data.Cmd`) not being
        // qualified to `this.Cmd`, so it misses the tainted receiver
        // field. See docs/goal.md §A.
        // The real flow `getParameter → Envelope.cmd → … → Runtime.exec`
        // is now detected (precise mode = 1) after the lang_java adapter
        // synthesizes the implicit `record` canonical constructor +
        // component accessors. In `--inferred-sources` mode two extra
        // narrowed `entry-point.class_field.inherited` findings appear on
        // the sibling record components `kind`/`user` — the whole-object
        // §C collapse (2026-05-28): `entry-point.class_field.inherited`
        // sources on sibling components (`this.kind`/`this.user`) are
        // now dropped when their field doesn't appear in the sink's
        // tainted_args, leaving just the real `req.getParameter →
        // Runtime.exec` finding.
        "java" => 1,
        "javascript" => 1,
        "kotlin" => 1,
        // Lua mega_flow has one real command-injection flow. The old count
        // included LuaSQL-shaped SQLi false positives on generic executor
        // calls without LuaSQL package evidence.
        "lua" => 1,
        "objc" => 1,
        "perl" => 2,
        // Two real vulns: readline → $envelope.cmd → … → shell_exec (CWE-78)
        // and readline → echo (CWE-79). Both reach their sink via real
        // chains (verified with `--source readline`). NOTE: the php adapter
        // models the `[...]` array literal / `[...$envelope]` spread as a
        // whole-container value (the destructuring `['cmd'=>$cmd]=$env`
        // emits no field link), so the combiner currently reports the
        // co-tainted `$_SERVER` (in the `user` field) as the representative
        // source instead of `readline`. Correct source attribution needs
        // php-adapter field-precision (array-literal field-writes + spread +
        // subscript-read field links) — see docs/goal.md.
        "php" => 2,
        // §C collapse (2026-05-28): one `class_field.inherited`
        // sibling-component over-approximation dropped now that
        // field-mismatched inferred sources are filtered when the
        // sink's tainted arg doesn't name the source's field. Then
        // (2026-05-29) the combiner's `group_id`-based dedup collapsed a
        // duplicate finding that reached `os_system@29` via a second
        // entry chain but carried the same `finding_id`. The stricter
        // projection/binding extraction now also folds the remaining
        // callable-object inferred evidence into the real Flask
        // `request.args.get` finding's member ids instead of emitting a
        // second user-visible row.
        "python" => 1,
        // The real `gets → system` path remains. The generic `data` blob
        // source is declaratively limited to insecure-deserialization sinks,
        // so constructor/factory parameters no longer create unrelated
        // command-injection findings.
        "ruby" => 1,
        "rust" => 1,
        // HttpServletRequest.getParameter → Envelope (case class) →
        // Pipeline.orchestrate (Option/for/case match) → Storage.persist
        // → Repository.wrap → AuditedRepository.run → super.run →
        // Repository.run → cmd accessor (`def cmd: String = data.cmd`)
        // → Executor.execute → Process .!: a real CWE-78 command-
        // injection through Scala's FN-language construct stack
        // (case classes, traits, Option, for-comprehensions, partial
        // functions). Unblocked 2026-05-27 by the lang_scala synthesis
        // additions (case-class ctor field-writes for params lacking
        // explicit `val`/`var` modifier — Scala promotes case-class
        // params to public vals implicitly; member-access accessor
        // rewritten as `Call+Return`; bare reads qualified with
        // explicit `Call` event; case-class component accessors
        // synthesized for cross-class field-projection).
        "scala" => 1,
        // In inferred-source mode Solidity reports one combined
        // audit-event information-exposure finding plus the external
        // `handle(raw) -> target.call(cmd)` reentrancy flow. The latter
        // starts at an inferred entry-point param because the concrete
        // bytes-calldata source rule is intentionally name-narrow.
        "solidity" => 2,
        // readLine() → Envelope (struct memberwise init) → Pipeline.orchestrate
        // (Optional/guard/case match) → Storage.persist → AuditedRepository
        // (inherits Repository.init via class chain) → super.run → Repository.run
        // → cmd computed property (`var cmd: String { data.cmd }`) → Envelope.cmd
        // accessor → Executor.execute → Process().launch with arguments=[..., cmd]:
        // a real CWE-78 command-injection through Swift's FN-language construct
        // stack (structs, computed properties, optionals, guard, switch, classes
        // with inheritance, `super`). Unblocked 2026-05-27 by the lang_swift
        // synthesis additions (memberwise init for structs + per-property
        // accessor methods so `data.cmd()` resolves to a callable; computed-
        // property `var X { expr }` synthesized as a Method whose body is
        // `Call+Return` for member-access expressions; bare property reads
        // qualified with an explicit `Call` event for walk_call's recv-slot
        // fallback; constructor implicit-Return synthesis so the init's param
        // tokens propagate to the caller's `repo` allocation at object level).
        // One real flow. The old inferred unreferenced-entry
        // over-approximation is now filtered once the concrete
        // readLine source covers the same sink site.
        "swift" => 1,
        "typescript" => 1,
        other => panic!("missing mega_flow expected finding count for {other}"),
    }
}

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

fn workspace_owned(files: Vec<(String, String)>) -> Workspace {
    let ws = Workspace::new(bonsai_adapters::all_languages_registry());
    for (path, src) in files {
        ws.vfs().write(path, Arc::<str>::from(src));
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

fn temp_real_workspace(tag: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let base = std::env::temp_dir();
    for attempt in 0..100 {
        let path = base.join(format!(
            "bonsai-security-{tag}-{}-{nanos}-{attempt}",
            std::process::id()
        ));
        match std::fs::create_dir(&path) {
            Ok(()) => return path,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => panic!("create temp workspace {}: {e}", path.display()),
        }
    }
    panic!("could not allocate temp workspace for {tag}");
}

fn rules_root() -> PathBuf {
    repo_root().join("security-patterns")
}

#[test]
fn inferred_class_field_sources_require_receiver_field_write() {
    let ws = workspace(&[(
        "app.py",
        r#"
class Holder:
    pass

class ReceiverState:
    def seed(self, value):
        self.value = value

    def receiver_leak(self):
        return self.value

class LocalOnly:
    def seed(self, value):
        holder = Holder()
        holder.value = value

    def local_leak(self):
        return holder.value
"#,
    )]);

    let sources = bonsai_security::infer_entry_point_sources(&ws);
    assert!(
        sources.iter().any(|source| {
            source.rule_id == "entry-point.class_field.inherited"
                && source.enclosing_fn.as_deref() == Some("receiver_leak")
                && source.match_text == "self.value"
        }),
        "receiver field should create inferred class-field source: {sources:#?}"
    );
    assert!(
        !sources.iter().any(|source| {
            source.rule_id == "entry-point.class_field.inherited"
                && source.enclosing_fn.as_deref() == Some("local_leak")
                && source.match_text == "holder.value"
        }),
        "local object field must not create inferred class-field source: {sources:#?}"
    );
}

#[test]
fn inferred_assigned_callables_remain_exactly_attributable() {
    let cases = [
        (
            "python",
            "/app/worker.py",
            "transform = lambda data: eval(data)\n",
            "transform",
        ),
        (
            "typescript",
            "/app/resolvers.ts",
            r#"
const resolvers = {
  users: (_parent: unknown, args: { query: string }) => eval(args.query),
};
"#,
            "users",
        ),
    ];

    for (language, path, source, expected_function) in cases {
        let ws = workspace(&[(path, source)]);
        let pack = constrained_call_sink_rulepack(language, "source", "eval");
        let report = run_taint_analysis(
            &ws,
            &pack,
            TaintAnalysisOptions {
                include_inferred_sources: true,
                ..TaintAnalysisOptions::default()
            },
        )
        .expect("taint analysis");
        assert!(
            report.analysis_complete,
            "{language} inferred callable attribution incomplete: {:?}",
            report.analysis_incomplete_reasons
        );
        assert!(
            report
                .findings
                .iter()
                .any(|finding| { finding.finding.sink.enclosing_fn.as_deref() == Some(expected_function) }),
            "{language} inferred callable did not reach eval: {:#?}",
            report.findings
        );
    }
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
            FlowEvent::AggregateAssign { .. } => {
                out.insert("AggregateAssign");
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
            typing: Vec::new(),
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
        analysis_semantics: None,
        taint_semantics: None,
        returns_type: None,
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
            typing: Vec::new(),
        },
    );
    pack
}

fn constrained_call_sink_rulepack(lang: &str, source_name: &str, sink_name: &str) -> Rulepack {
    let mut pack = Rulepack::default();
    let mut sink = rule(
        lang,
        RuleKind::Sink,
        &format!("{lang}.test.call_sink"),
        None,
        Some(Severity::Critical),
        sink_name,
    );
    sink.constraints = RuleConstraint(vec![ConstraintKind::ArgTainted {
        arg_tainted: ArgTaintedSpec {
            index: Some(0),
            kw: None,
        },
    }]);
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
            sinks: vec![sink],
            sanitizers: Vec::new(),
            typing: Vec::new(),
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
        source_callback_args: Vec::new(),
        call_result_passthrough_args: Vec::new(),
        call_result_passthrough_receiver: false,
        output_arg_flows: Vec::new(),
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
            typing: Vec::new(),
        },
    );
    pack
}

fn go_bind_output_rulepack() -> Rulepack {
    let mut source = rule(
        "go",
        RuleKind::Source,
        "go.test.bind_output_source",
        Some(TrustClass::Remote),
        None,
        "BindJSON",
    );
    source.taint_semantics = Some(TaintSemantics {
        clean_output_overwrite: None,
        source_output_args: vec![0],
        source_callback_args: Vec::new(),
        call_result_passthrough_args: Vec::new(),
        call_result_passthrough_receiver: false,
        output_arg_flows: Vec::new(),
        taint_receiver_from_args: false,
    });
    let mut sink = rule(
        "go",
        RuleKind::Sink,
        "go.test.command_sink",
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
    let mut pack = Rulepack::default();
    pack.packs.insert(
        "go".to_string(),
        LanguagePack {
            language: "go".to_string(),
            sources: vec![source],
            sinks: vec![sink],
            sanitizers: Vec::new(),
            typing: Vec::new(),
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
        analysis_semantics: None,
        taint_semantics: None,
        returns_type: None,
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
fn go_write_back_source_keeps_exact_ast_output_carrier_through_scheduling() {
    let ws = workspace(&[
        (
            "handler.go",
            r#"
package fixture

type Context struct{}
type Request struct{ URL string }

func (c *Context) BindJSON(dst any) error { return nil }

func handle(c *Context) {
    var body Request
    if err := c.BindJSON(&body); err != nil {
        return
    }
    forward(body.URL)
}
"#,
        ),
        (
            "service.go",
            r#"
package fixture

func forward(url string) {
    dangerous(url)
}

func dangerous(value string) {}
"#,
        ),
    ]);
    let report = run_taint_analysis(
        &ws,
        &go_bind_output_rulepack(),
        TaintAnalysisOptions {
            include_inferred_sources: false,
            ..Default::default()
        },
    )
    .expect("taint analysis");
    assert_eq!(
        report.findings.len(),
        1,
        "the exact write-back carrier from the parsed call must survive the memory-light linkage snapshot: {:#?}",
        report.findings
    );
}

#[test]
fn go_aggregate_call_source_taints_parsed_descendant_after_tuple_binding() {
    let ws = workspace(&[(
        "main.go",
        r#"
package fixture

type Result struct{ Value string }

func source() (*Result, error) { return &Result{}, nil }
func sink(value string) {}

func handle() {
    result, _ := source()
    sink(result.Value)
}
"#,
    )]);
    let report = run_taint_analysis(
        &ws,
        &rulepack("go", "source", "sink"),
        TaintAnalysisOptions {
            include_inferred_sources: false,
            ..Default::default()
        },
    )
    .expect("taint analysis");
    assert_eq!(
        report.findings.len(),
        1,
        "the parsed tuple binding identifies the aggregate returned by the source call: {:#?}",
        report.findings
    );
}

#[test]
fn go_dynamic_lookup_key_does_not_taint_trusted_map_value() {
    let ws = workspace(&[(
        "/app/main.go",
        r#"
package main

var pages = map[string]string{
    "home": "<h1>home</h1>",
    "about": "<h1>about</h1>",
}

func source() string { return "" }
func sink(value string) {}
func fail(value string) error { return nil }

func render(name string) (string, error) {
    value, ok := pages[name]
    if !ok { return "", fail(name) }
    return value, nil
}

func safe() {
    name := source()
    value, _ := render(name)
    sink(value)
}
func unsafe() { sink(source()) }
"#,
    )]);
    let report = run_taint_analysis(
        &ws,
        &rulepack("go", "source", "sink"),
        TaintAnalysisOptions::default(),
    )
    .expect("taint analysis");
    assert!(
        report
            .findings
            .iter()
            .any(|finding| finding.finding.sink.enclosing_fn.as_deref() == Some("unsafe")),
        "direct source-to-sink control must remain detected: {:#?}",
        report.findings
    );
    assert!(
        report
            .findings
            .iter()
            .all(|finding| finding.finding.sink.enclosing_fn.as_deref() != Some("safe")),
        "a selector key chooses a trusted stored value but does not become that value: {:#?}",
        report.findings
    );
}

#[test]
fn taint_analysis_populates_bounded_workspace_graph_cache() {
    let ws = workspace(&[(
        "/w/app.py",
        "def source():\n    return input()\n\ndef sink(value):\n    pass\n\ndef entry():\n    value = source()\n    sink(value)\n",
    )]);
    let pack = rulepack("python", "source", "sink");

    assert_eq!(ws.taint_index().resident_len(), 0);
    assert!(
        ws.db().idg_service().is_none(),
        "taint-analysis fixture must start without a canonical IDG"
    );
    let first = run_taint_analysis(&ws, &pack, TaintAnalysisOptions::default()).expect("first analysis");
    assert!(
        !first.findings.is_empty(),
        "fixture should prove at least one source-to-sink flow"
    );
    let populated = ws.taint_index().resident_len();
    assert!(
        populated > 0,
        "analysis should publish exact graphs to the workspace cache"
    );
    assert!(
        populated <= ws.taint_index().resident_capacity(),
        "workspace graph cache must stay within its resident cap"
    );

    let second = run_taint_analysis(&ws, &pack, TaintAnalysisOptions::default()).expect("second analysis");
    assert_eq!(second.findings.len(), first.findings.len());
    assert_eq!(
        ws.taint_index().resident_len(),
        populated,
        "repeat analysis with the same rule/config fingerprint should reuse existing graph keys"
    );
    assert!(
        ws.db().idg_service().is_none(),
        "taint-analysis must not publish its source/sink-scoped IDG as the canonical default"
    );
}

#[test]
fn taint_graph_disk_namespace_changes_with_semantic_idg_scope() {
    let root = temp_real_workspace("taint-scope-identity");
    std::fs::write(
        root.join("source_a.py"),
        "def source_a():\n    return input()\n\ndef sink_a(value):\n    return value\n\ndef entry_a():\n    sink_a(source_a())\n",
    )
    .expect("write source A fixture");
    std::fs::write(
        root.join("source_b.py"),
        "def source_b():\n    return input()\n\ndef sink_b(value):\n    return value\n\ndef entry_b():\n    sink_b(source_b())\n",
    )
    .expect("write source B fixture");

    let mut pack = Rulepack::default();
    pack.packs.insert(
        "python".to_string(),
        LanguagePack {
            language: "python".to_string(),
            sources: vec![
                rule(
                    "python",
                    RuleKind::Source,
                    "python.test.source_a",
                    Some(TrustClass::Remote),
                    None,
                    "source_a",
                ),
                rule(
                    "python",
                    RuleKind::Source,
                    "python.test.source_b",
                    Some(TrustClass::Remote),
                    None,
                    "source_b",
                ),
            ],
            sinks: vec![
                rule(
                    "python",
                    RuleKind::Sink,
                    "python.test.sink_a",
                    None,
                    Some(Severity::Critical),
                    "sink_a",
                ),
                rule(
                    "python",
                    RuleKind::Sink,
                    "python.test.sink_b",
                    None,
                    Some(Severity::Critical),
                    "sink_b",
                ),
            ],
            sanitizers: Vec::new(),
            typing: Vec::new(),
        },
    );
    let ws = Workspace::index(&root, bonsai_adapters::all_languages_registry()).expect("index scope fixture");

    let run_scope = |source_rule: &str| {
        let mut sidecar = None;
        let report = run_taint_analysis_with_phase_progress(
            &ws,
            &pack,
            TaintAnalysisOptions {
                source: Some(format!("^{source_rule}$")),
                include_inferred_sources: false,
                ..Default::default()
            },
            |event| {
                if let bonsai_security::AnalysisProgress::Note { label, detail } = event {
                    if label == "taint-cache" {
                        if let Some(path) = detail
                            .split(';')
                            .map(str::trim)
                            .find_map(|part| part.strip_prefix("sidecar="))
                            .filter(|path| *path != "none")
                            .map(PathBuf::from)
                        {
                            sidecar = Some(path);
                        }
                    }
                }
            },
        )
        .expect("taint analysis for scoped cache identity");
        assert!(!report.findings.is_empty(), "{source_rule}: expected a real flow");
        sidecar.expect("scoped taint analysis should report its disk sidecar")
    };

    let source_a_sidecar = run_scope("python\\.test\\.source_a");
    let source_b_sidecar = run_scope("python\\.test\\.source_b");
    assert_ne!(
        source_a_sidecar, source_b_sidecar,
        "different semantic IDG scopes must never reuse one taint graph sidecar"
    );
    assert!(
        source_a_sidecar.exists(),
        "missing {}",
        source_a_sidecar.display()
    );
    assert!(
        source_b_sidecar.exists(),
        "missing {}",
        source_b_sidecar.display()
    );

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn benchmark_shaped_security_flows_reach_sink() {
    for fixture in fixtures() {
        assert_finding(fixture);
    }
}

#[test]
fn taint_analysis_covers_every_source_group_in_a_wide_scan() {
    let ws = Workspace::new(bonsai_adapters::all_languages_registry());
    for i in 0..12 {
        let path = format!("/app/case_{i}.py");
        let src = format!(
            "def source():\n    return \"\"\n\n\
             def sink(x):\n    pass\n\n\
             def handle_{i}():\n    value = source()\n    sink(value)\n"
        );
        ws.vfs().write(path, Arc::<str>::from(src));
    }
    for file in ws.vfs().all_files() {
        let _ = ws.db().decl_index(file);
        let _ = ws.db().import_index(file);
    }
    let report = run_taint_analysis(
        &ws,
        &rulepack("python", "source", "sink"),
        TaintAnalysisOptions::default(),
    )
    .expect("taint analysis");
    let sink_files: BTreeSet<_> = report
        .findings
        .iter()
        .map(|finding| finding.finding.sink.file.clone())
        .collect();
    assert_eq!(
        sink_files.len(),
        12,
        "security taint-analysis must evaluate every source group; findings={:#?}",
        report.findings
    );
}

#[test]
fn taint_analysis_schedules_only_source_groups_that_can_reach_sinks() {
    let ws = Workspace::new(bonsai_adapters::all_languages_registry());
    ws.vfs().write(
        "/app/Real.java".to_string(),
        Arc::<str>::from(
            "package app;\n\
             class Real {\n\
             \n  String source() { return \"\"; }\n\
             \n  static void sink(String value) {}\n\
             \n  void handle() { sink(source()); }\n\
             }\n",
        ),
    );
    for i in 0..64 {
        ws.vfs().write(
            format!("/app/Unreachable{i:02}.java"),
            Arc::<str>::from(format!(
                "package app;\n\
                 class Unreachable{i:02} {{\n\
                 \n  String source() {{ return \"\"; }}\n\
                 \n  String handle() {{ String value = source(); return value; }}\n\
                 }}\n"
            )),
        );
    }
    for file in ws.vfs().all_files() {
        let _ = ws.db().decl_index(file);
        let _ = ws.db().import_index(file);
    }

    let mut current_phase: Option<&'static str> = None;
    let mut taint_chain_total = None;
    let mut taint_chain_ticks = 0u64;
    let mut notes: Vec<(&'static str, String)> = Vec::new();
    let report = bonsai_security::run_taint_analysis_with_phase_progress(
        &ws,
        &rulepack("java", "source", "sink"),
        TaintAnalysisOptions::default(),
        |event| match event {
            bonsai_security::AnalysisProgress::PhaseStarted { label, total } => {
                current_phase = Some(label);
                if label == "building taint chains" {
                    taint_chain_total = Some(total);
                }
            }
            bonsai_security::AnalysisProgress::PhaseTicked => {
                if current_phase == Some("building taint chains") {
                    taint_chain_ticks += 1;
                }
            }
            bonsai_security::AnalysisProgress::PhaseFinished => {
                current_phase = None;
            }
            bonsai_security::AnalysisProgress::Note { label, detail } => {
                notes.push((label, detail));
            }
        },
    )
    .expect("taint analysis");

    assert_eq!(taint_chain_total, Some(1));
    assert_eq!(taint_chain_ticks, 1);
    assert!(
        notes
            .iter()
            .any(|(label, detail)| *label == "scope" && detail.contains("taint-analysis files=")),
        "taint-analysis should report scan scope through SDK progress notes: {notes:#?}"
    );
    assert!(
        notes.iter().any(|(label, detail)| {
            *label == "scope"
                && detail.contains("taint-analysis source_matches=")
                && detail.contains("static_evidence=exact+narrowed")
                && !detail.contains("max_precision")
        }),
        "taint-analysis should report the public static-evidence contract through SDK progress notes: {notes:#?}"
    );
    assert!(
        notes.iter().any(|(label, detail)| {
            *label == "taint-cache"
                && (detail.contains("miss")
                    || detail.contains("hit")
                    || detail.contains("config changed")
                    || detail.contains("skipped"))
        }),
        "taint-analysis should report taint cache hit/miss state through SDK progress notes: {notes:#?}"
    );
    assert!(
        !notes
            .iter()
            .any(|(label, detail)| *label == "taint-cache" && detail == "finish write-through failed"),
        "a cache writer that was never started must not be reported as a finish failure: {notes:#?}"
    );
    assert_eq!(report.findings.len(), 1, "{:#?}", report.findings);
    assert!(
        report.findings[0].finding.source.file.contains("Real.java"),
        "unreachable source-only files must not be walked into findings: {:#?}",
        report.findings
    );
}

#[test]
fn taint_analysis_source_to_sink_scheduler_filters_unreachable_sources_for_every_language() {
    for lang in ALL_LANGS {
        let ws = workspace_owned(scheduler_filter_fixture(lang, 8));
        let mut current_phase: Option<&'static str> = None;
        let mut taint_chain_total = None;
        let mut taint_chain_ticks = 0u64;
        let report = bonsai_security::run_taint_analysis_with_phase_progress(
            &ws,
            &rulepack(lang, "source", "sink"),
            TaintAnalysisOptions::default(),
            |event| match event {
                bonsai_security::AnalysisProgress::PhaseStarted { label, total } => {
                    current_phase = Some(label);
                    if label == "building taint chains" {
                        taint_chain_total = Some(total);
                    }
                }
                bonsai_security::AnalysisProgress::PhaseTicked => {
                    if current_phase == Some("building taint chains") {
                        taint_chain_ticks += 1;
                    }
                }
                bonsai_security::AnalysisProgress::PhaseFinished => {
                    current_phase = None;
                }
                bonsai_security::AnalysisProgress::Note { .. } => {}
            },
        )
        .unwrap_or_else(|err| panic!("{lang}: taint analysis failed: {err}"));

        assert_eq!(
            taint_chain_total,
            Some(1),
            "{lang}: source-to-sink scheduler must not schedule unreachable source-only groups; findings={:#?}",
            report.findings
        );
        assert_eq!(
            taint_chain_ticks, 1,
            "{lang}: source-to-sink scheduler walked more groups than the semantic corridor"
        );
        assert!(
            !report.findings.is_empty(),
            "{lang}: real source-to-sink flow must still be reported"
        );
        assert!(
            report.findings.iter().all(|finding| {
                !finding.finding.source.file.contains("Unreachable")
                    && !finding.finding.sink.file.contains("Unreachable")
            }),
            "{lang}: unreachable source-only functions leaked into findings: {:#?}",
            report.findings
        );
    }
}

#[test]
fn source_analysis_progress_emits_scope_and_cache_notes_to_sdk() {
    let ws = workspace(&[(
        "/app/app.py",
        "def source():\n    return input()\n\n\
         def handle():\n    value = source()\n    return value\n",
    )]);
    assert!(
        ws.db().idg_service().is_none(),
        "source-analysis fixture must start without a canonical IDG"
    );
    let mut notes: Vec<(&'static str, String)> = Vec::new();
    let report = bonsai_security::run_source_analysis_with_phase_progress(
        &ws,
        &rulepack("python", "source", "sink"),
        SourceAnalysisOptions::default(),
        |event| {
            if let bonsai_security::AnalysisProgress::Note { label, detail } = event {
                notes.push((label, detail));
            }
        },
    )
    .expect("source analysis");

    assert!(
        !report.candidates.is_empty(),
        "fixture should produce at least one source-analysis candidate"
    );
    assert!(
        notes
            .iter()
            .any(|(label, detail)| *label == "scope" && detail.contains("source-analysis files=")),
        "source-analysis should report scan scope through SDK progress notes: {notes:#?}"
    );
    assert!(
        notes.iter().any(|(label, detail)| {
            *label == "taint-cache"
                && (detail.contains("miss")
                    || detail.contains("hit")
                    || detail.contains("config changed")
                    || detail.contains("skipped"))
        }),
        "source-analysis should report taint cache hit/miss state through SDK progress notes: {notes:#?}"
    );
    assert!(
        !notes
            .iter()
            .any(|(label, detail)| *label == "taint-cache" && detail == "finish write-through failed"),
        "a cache writer that was never started must not be reported as a finish failure: {notes:#?}"
    );
    assert!(
        ws.db().idg_service().is_none(),
        "source-analysis must retain its scoped IDG explicitly instead of publishing it as the canonical default"
    );
}

#[test]
fn source_analysis_render_hop_limit_does_not_limit_analyzed_scope() {
    let mut source = String::from(
        "def source():\n    return 'tainted'\n\ndef entry():\n    value = source()\n    hop1(value)\n\n",
    );
    for hop in 1..8 {
        writeln!(source, "def hop{hop}(value):\n    hop{}(value)\n", hop + 1)
            .expect("write deep source-analysis fixture");
    }
    source.push_str("def hop8(value):\n    consume(value)\n");

    let ws = workspace(&[("/app/deep.py", source.as_str())]);
    let pack = rulepack("python", "source", "sink");
    let bounded = bonsai_security::run_source_analysis(&ws, &pack, SourceAnalysisOptions::default())
        .expect("bounded source analysis");

    assert!(
        bounded
            .candidates
            .iter()
            .any(|candidate| candidate.lineage.truncated_hops),
        "the complete analyzed graph must expose that the representative six-hop rendering truncated a deeper flow: {:#?}",
        bounded.candidates
    );
    assert!(
        !bounded.lineage_summary.is_complete(),
        "a truncated representative lineage must be reported as incomplete"
    );

    let unbounded = bonsai_security::run_source_analysis(
        &ws,
        &pack,
        SourceAnalysisOptions {
            lineage_limits: SourceLineageLimits::unbounded(),
            ..Default::default()
        },
    )
    .expect("unbounded source analysis");
    assert!(
        unbounded
            .candidates
            .iter()
            .any(|candidate| candidate.chain_names.last().is_some_and(|name| name == "hop8")),
        "rendering without limits must expose the analyzed terminal hop: {:#?}",
        unbounded.candidates
    );
    assert!(
        unbounded.lineage_summary.is_complete(),
        "an unbounded rendering over the same complete graph must be complete: {:#?}",
        unbounded.lineage_summary
    );
}

#[test]
fn taint_analysis_taint_graph_sidecar_is_default_on_and_reused_from_disk() {
    let root = temp_real_workspace("taint-sidecar-default");
    std::fs::write(
        root.join("app.py"),
        r#"
def source():
    return input()

def sink(value):
    return value

def handle():
    value = source()
    return sink(value)
"#,
    )
    .expect("write python fixture");
    let pack = rulepack("python", "source", "sink");

    let run_once = || {
        let ws =
            Workspace::index(&root, bonsai_adapters::all_languages_registry()).expect("index real workspace");
        let mut notes: Vec<(&'static str, String)> = Vec::new();
        let report = bonsai_security::run_taint_analysis_with_phase_progress(
            &ws,
            &pack,
            TaintAnalysisOptions::default(),
            |event| {
                if let bonsai_security::AnalysisProgress::Note { label, detail } = event {
                    notes.push((label, detail));
                }
            },
        )
        .expect("taint analysis");
        (report.findings.len(), notes)
    };

    let (first_findings, first_notes) = run_once();
    let sidecar = bonsai_workspace::taint_index::TaintGraphIndex::latest_sidecar_path(&root);
    assert!(
        first_findings > 0,
        "initial run should find the fixture; notes={first_notes:#?}"
    );
    assert!(
        sidecar.is_file(),
        "default taint analysis should write the taint graph sidecar at {}",
        sidecar.display()
    );
    assert!(
        std::fs::metadata(&sidecar).map_or(0, |meta| meta.len()) > 0,
        "taint graph sidecar should not be empty"
    );
    assert!(
        first_notes
            .iter()
            .any(|(label, detail)| { *label == "taint-cache" && detail.contains("write-through on") }),
        "initial run should report write-through persistence through SDK progress notes: {first_notes:#?}"
    );

    let (second_findings, second_notes) = run_once();
    assert_eq!(
        second_findings, first_findings,
        "warm sidecar reuse must not change findings"
    );
    assert!(
        second_notes.iter().any(|(label, detail)| {
            *label == "taint-cache" && detail.contains("disk hit") && !detail.contains("disk_entries=0")
        }),
        "second run should report taint graph sidecar reuse through SDK progress notes: {second_notes:#?}"
    );
}

fn scheduler_filter_fixture(lang: &str, unreachable_count: usize) -> Vec<(String, String)> {
    let unreachable_names: Vec<String> = (0..unreachable_count)
        .map(|idx| format!("unreachable_{idx}"))
        .collect();
    match lang {
        "c" => vec![(
            "/app/main.c".to_string(),
            c_like_scheduler_fixture("", "", &unreachable_names),
        )],
        "cpp" => vec![(
            "/app/main.cpp".to_string(),
            c_like_scheduler_fixture(
                "#include <string>\n",
                "std::string",
                &unreachable_names,
            ),
        )],
        "csharp" => vec![(
            "/app/App.cs".to_string(),
            class_method_scheduler_fixture(
                "class App {\n",
                "  string source() { return \"\"; }\n  void sink(string value) {}\n  void handle() { sink(source()); }\n",
                "  string",
                &unreachable_names,
                "}\n",
            ),
        )],
        "dart" => vec![(
            "/app/app.dart".to_string(),
            top_level_scheduler_fixture(
                "String source() => \"\";\nvoid sink(String value) {}\nvoid handle() { sink(source()); }\n",
                "String",
                &unreachable_names,
                "() => source();\n",
            ),
        )],
        "elixir" => vec![(
            "/app/app.ex".to_string(),
            format!(
                "defmodule App do\n  def source(), do: \"\"\n  def sink(_value), do: :ok\n  def handle(), do: sink(source())\n{}end\n",
                render_unreachable_defs(&unreachable_names, |out, name| {
                    writeln!(out, "  def {name}(), do: source()").unwrap();
                })
            ),
        )],
        "erlang" => {
            let exports = std::iter::once("handle/0".to_string())
                .chain(std::iter::once("source/0".to_string()))
                .chain(std::iter::once("sink/1".to_string()))
                .chain(unreachable_names.iter().map(|name| format!("{name}/0")))
                .collect::<Vec<_>>()
                .join(", ");
            vec![(
                "/app/app.erl".to_string(),
                format!(
                    "-module(app).\n-export([{exports}]).\nsource() -> \"\".\nsink(_Value) -> ok.\nhandle() -> sink(source()).\n{}",
                    render_unreachable_defs(&unreachable_names, |out, name| {
                        writeln!(out, "{name}() -> source().").unwrap();
                    })
                ),
            )]
        }
        "go" => vec![(
            "/app/main.go".to_string(),
            top_level_scheduler_fixture(
                "package main\nfunc source() string { return \"\" }\nfunc sink(value string) {}\nfunc handle() { sink(source()) }\n",
                "func",
                &unreachable_names,
                "() string { return source() }\n",
            ),
        )],
        "java" => vec![(
            "/app/App.java".to_string(),
            class_method_scheduler_fixture(
                "class App {\n",
                "  String source() { return \"\"; }\n  static void sink(String value) {}\n  void handle() { sink(source()); }\n",
                "  String",
                &unreachable_names,
                "}\n",
            ),
        )],
        "javascript" => vec![(
            "/app/app.js".to_string(),
            js_like_scheduler_fixture("", "", &unreachable_names),
        )],
        "kotlin" => vec![(
            "/app/App.kt".to_string(),
            top_level_scheduler_fixture(
                "fun source(): String = \"\"\nfun sink(value: String) {}\nfun handle() { sink(source()) }\n",
                "fun",
                &unreachable_names,
                "(): String = source()\n",
            ),
        )],
        "lua" => vec![(
            "/app/app.lua".to_string(),
            format!(
                "local function source() return \"\" end\nlocal function sink(value) end\nlocal function handle() sink(source()) end\n{}",
                render_unreachable_defs(&unreachable_names, |out, name| {
                    writeln!(out, "local function {name}() return source() end").unwrap();
                })
            ),
        )],
        "objc" => vec![(
            "/app/main.m".to_string(),
            c_like_scheduler_fixture("", "", &unreachable_names),
        )],
        "perl" => vec![(
            "/app/app.pl".to_string(),
            format!(
                "sub source {{ return \"\"; }}\nsub sink {{ my ($value) = @_; }}\nsub handle {{ sink(source()); }}\n{}1;\n",
                render_unreachable_defs(&unreachable_names, |out, name| {
                    writeln!(out, "sub {name} {{ return source(); }}").unwrap();
                })
            ),
        )],
        "php" => vec![(
            "/app/app.php".to_string(),
            format!(
                "<?php\nfunction source() {{ return \"\"; }}\nfunction sink($value) {{}}\nfunction handle() {{ sink(source()); }}\n{}",
                render_unreachable_defs(&unreachable_names, |out, name| {
                    writeln!(out, "function {name}() {{ return source(); }}").unwrap();
                })
            ),
        )],
        "python" => vec![(
            "/app/app.py".to_string(),
            format!(
                "def source():\n    return \"\"\n\ndef sink(value):\n    pass\n\ndef handle():\n    sink(source())\n\n{}",
                render_unreachable_defs(&unreachable_names, |out, name| {
                    writeln!(out, "def {name}():\n    return source()\n").unwrap();
                })
            ),
        )],
        "ruby" => vec![(
            "/app/app.rb".to_string(),
            format!(
                "def source; \"\"; end\ndef sink(value); end\ndef handle; sink(source()); end\n{}",
                render_unreachable_defs(&unreachable_names, |out, name| {
                    writeln!(out, "def {name}; source(); end").unwrap();
                })
            ),
        )],
        "rust" => vec![(
            "/app/main.rs".to_string(),
            top_level_scheduler_fixture(
                "fn source() -> String { String::new() }\nfn sink(value: String) {}\nfn handle() { sink(source()); }\n",
                "fn",
                &unreachable_names,
                "() -> String { source() }\n",
            ),
        )],
        "scala" => vec![(
            "/app/App.scala".to_string(),
            format!(
                "object App {{\n  def source(): String = \"\"\n  def sink(value: String): Unit = ()\n  def handle(): Unit = sink(source())\n{} }}\n",
                render_unreachable_defs(&unreachable_names, |out, name| {
                    writeln!(out, "  def {name}(): String = source()").unwrap();
                })
            ),
        )],
        "solidity" => vec![(
            "/app/App.sol".to_string(),
            format!(
                "pragma solidity ^0.8.0;\ncontract App {{\n  function source() internal pure returns (bytes memory) {{ return \"\"; }}\n  function sink(bytes memory value) internal pure {{}}\n  function handle() external {{ sink(source()); }}\n{} }}\n",
                render_unreachable_defs(&unreachable_names, |out, name| {
                    writeln!(
                        out,
                        "  function {name}() external pure returns (bytes memory) {{ return source(); }}"
                    )
                    .unwrap();
                })
            ),
        )],
        "swift" => vec![(
            "/app/App.swift".to_string(),
            top_level_scheduler_fixture(
                "func source() -> String { return \"\" }\nfunc sink(_ value: String) {}\nfunc handle() { sink(source()) }\n",
                "func",
                &unreachable_names,
                "() -> String { return source() }\n",
            ),
        )],
        "typescript" => vec![(
            "/app/app.ts".to_string(),
            js_like_scheduler_fixture(": string", ": void", &unreachable_names),
        )],
        other => panic!("missing scheduler fixture for {other}"),
    }
}

fn c_like_scheduler_fixture(prefix: &str, string_type: &str, unreachable_names: &[String]) -> String {
    let ty = if string_type.is_empty() {
        "char *"
    } else {
        string_type
    };
    format!(
        "{prefix}{ty} source(void) {{ return \"\"; }}\nvoid sink({ty} value) {{}}\nvoid handle(void) {{ sink(source()); }}\n{}",
        render_unreachable_defs(unreachable_names, |out, name| {
            writeln!(out, "{ty} {name}(void) {{ return source(); }}").unwrap();
        })
    )
}

fn class_method_scheduler_fixture(
    prefix: &str,
    body: &str,
    return_type_prefix: &str,
    unreachable_names: &[String],
    suffix: &str,
) -> String {
    format!(
        "{prefix}{body}{}{suffix}",
        render_unreachable_defs(unreachable_names, |out, name| {
            writeln!(out, "{return_type_prefix} {name}() {{ return source(); }}").unwrap();
        })
    )
}

fn top_level_scheduler_fixture(
    prefix: &str,
    keyword_or_type: &str,
    unreachable_names: &[String],
    suffix: &str,
) -> String {
    format!(
        "{prefix}{}",
        render_unreachable_defs(unreachable_names, |out, name| {
            write!(out, "{keyword_or_type} {name}{suffix}").unwrap();
        })
    )
}

fn js_like_scheduler_fixture(
    source_return_type: &str,
    sink_return_type: &str,
    unreachable_names: &[String],
) -> String {
    format!(
        "function source(){source_return_type} {{ return \"\"; }}\nfunction sink(value{source_return_type}){sink_return_type} {{}}\nfunction handle(){sink_return_type} {{ sink(source()); }}\n{}",
        render_unreachable_defs(unreachable_names, |out, name| {
            writeln!(out, "function {name}(){source_return_type} {{ return source(); }}").unwrap();
        })
    )
}

fn render_unreachable_defs<F>(unreachable_names: &[String], mut render: F) -> String
where
    F: FnMut(&mut String, &str),
{
    let mut out = String::new();
    for name in unreachable_names {
        render(&mut out, name);
    }
    out
}

#[test]
fn call_argument_lambda_body_has_single_finding_owner() {
    let ws = workspace(&[(
        "/app/app.js",
        r#"
function source() { return ""; }
function sink(value) {}

function main(app) {
  app.post("/eval", function(ctx) {
    const body = source();
    sink(body);
  });
}
"#,
    )]);
    let report = run_taint_analysis(
        &ws,
        &rulepack("javascript", "source", "sink"),
        TaintAnalysisOptions::default(),
    )
    .expect("taint analysis");
    let matching: Vec<_> = report
        .findings
        .iter()
        .filter(|finding| finding.finding.sink.file.contains("app.js"))
        .collect();
    assert_eq!(
        matching.len(),
        1,
        "call-argument lambda bodies must not be owned by both outer function and synthetic lambda decl; findings={:#?}",
        report.findings
    );
    assert!(
        matching[0]
            .finding
            .chain_display
            .iter()
            .all(|name| !name.starts_with("<lambda@")),
        "call-argument lambda body should be attributed through the enclosing function, got {:#?}",
        matching[0].finding.chain_display
    );
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

        let expected = expected_mega_flow_findings_with_inferred_sources(lang);
        assert_eq!(
            report.findings.len(),
            expected,
            "{lang}: mega_flow finding count drifted; findings={:#?}",
            report.findings
        );
        if expected > 0 {
            assert!(
                report
                    .findings
                    .iter()
                    .any(|finding| finding.finding.chain_display.len() >= 2),
                "{lang}: mega_flow must include at least one multi-hop source-to-sink chain; findings={:#?}",
                report.findings
            );
        }
        if *lang == "go" {
            let go_cmd = report
                .findings
                .iter()
                .find(|finding| finding.finding.sink.rule_id == "go.cmdi.exec_command_shell_wrapper")
                .expect("go command-injection flow");
            assert_eq!(go_cmd.finding.source.rule_id, "go.nethttp.query_value_get");
            assert_eq!(go_cmd.finding.source.line, 33, "{go_cmd:#?}");
        }
        if *lang == "objc" {
            let objc_cmd = report
                .findings
                .iter()
                .find(|finding| finding.finding.sink.rule_id == "objc.cmdi.system")
                .expect("objc command-injection flow");
            assert_eq!(objc_cmd.finding.source.rule_id, "objc.source.stdin_fgets");
            assert_eq!(objc_cmd.finding.source.line, 15, "{objc_cmd:#?}");
            assert!(
                report
                    .findings
                    .iter()
                    .all(|finding| finding.finding.sink.rule_id != "objc.xxe.nsxmlparser_initwithdata"),
                "repository initWithData: must not be reported as NSXMLParser XXE: {:#?}",
                report.findings
            );
        }
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
fn rust_mega_flow_preserves_nested_field_projection_through_newtype_factory() {
    let ws = index_real_fixture("rust", "mega_flow");
    let source = ws
        .lookup_function("handle_request")
        .expect("Rust mega-flow entry");
    let global = ws.db().global_index();
    let idg = ensure_idg_service(ws.db());
    let seeds = TokenSet::from_iter(["raw".to_string()]);
    let seed_nodes = compose_idg_seed_nodes(
        IdgSeedRequest::token_api(source, &seeds),
        global.as_ref(),
        idg.as_ref(),
    );
    let closure = idg.forward_closure(&seed_nodes);
    let (execute_caller, execute_span) = ws
        .vfs()
        .all_files()
        .into_iter()
        .flat_map(|file| global.decls_in(file).iter())
        .filter(|decl| decl.name == "run")
        .find_map(|decl| {
            decl.flow_events.iter().find_map(|event| match event {
                FlowEvent::Call { span, name, .. } if name == "executor::execute" => {
                    Some((bonsai_common::FuncId::new(decl.symbol.raw()), span.to_owned()))
                }
                _ => None,
            })
        })
        .expect("Repository::run execute call");
    let points = closure
        .iter()
        .filter_map(|node| idg.resolve_point(*node))
        .collect::<Vec<_>>();
    let execute_nodes = idg.nodes_at_span(execute_caller, execute_span);
    let orchestrate = ws.lookup_function("orchestrate").expect("Rust pipeline function");
    let projection_diagnostics = ["joined", "routed", "valid.cmd", "valid.user"].map(|name| {
        let nodes = idg.read_or_write_nodes_for_names(orchestrate, &[name.to_string()]);
        let rows = nodes
            .iter()
            .map(|node| {
                (
                    *node,
                    closure.contains(node),
                    execute_nodes.iter().any(|target| idg.reaches(*node, *target)),
                    idg.resolve_point(*node),
                )
            })
            .collect::<Vec<_>>();
        (name, rows)
    });

    assert!(
        points.iter().any(|point| {
            point.kind == PointKind::CallArg && point.span == execute_span && point.name == "arg0"
        }),
        "raw -> Envelope.cmd -> wrapper tuple field must reach execute(arg0); projections={projection_diagnostics:#?}; closure={points:#?}"
    );
}

#[test]
fn kotlin_mega_flow_preserves_implicit_getter_receiver_state() {
    let ws = index_real_fixture("kotlin", "mega_flow");
    let global = ws.db().global_index();
    let idg = ensure_idg_service(ws.db());
    let handle = ws.lookup_function("handle").expect("Kotlin mega-flow entry");
    let seeds = TokenSet::from_iter(["raw".to_string()]);
    let seed_nodes = compose_idg_seed_nodes(
        IdgSeedRequest::token_api(handle, &seeds),
        global.as_ref(),
        idg.as_ref(),
    );
    let closure = idg.forward_closure(&seed_nodes);
    let (repository_run, execute_span) = ws
        .vfs()
        .all_files()
        .into_iter()
        .flat_map(|file| global.decls_in(file).iter())
        .filter(|decl| decl.name == "run")
        .find_map(|decl| {
            decl.flow_events.iter().find_map(|event| match event {
                FlowEvent::Call { span, name, .. } if name == "Executor.execute" => {
                    Some((bonsai_common::FuncId::new(decl.symbol.raw()), *span))
                }
                _ => None,
            })
        })
        .expect("Repository.run execute call");
    let execute_nodes = idg.nodes_at_span(repository_run, execute_span);
    let points = closure
        .iter()
        .filter_map(|node| idg.resolve_point(*node))
        .collect::<Vec<_>>();

    assert!(
        execute_nodes.iter().any(|node| {
            closure.contains(node)
                && idg
                    .resolve_point(*node)
                    .is_some_and(|point| point.kind == PointKind::CallArg && point.name == "arg0")
        }),
        "raw -> constructor state -> implicit cmd getter must reach Executor.execute(c); \
         execute_nodes={execute_nodes:#?}; closure={points:#?}"
    );
}

#[test]
fn dart_mega_flow_stitches_repository_argument_into_execute_parameter() {
    let ws = index_real_fixture("dart", "mega_flow");
    let global = ws.db().global_index();
    let idg = ensure_idg_service(ws.db());
    let execute = ws.lookup_function("execute").expect("Dart executor function");
    let (repository_run, execute_span) = ws
        .vfs()
        .all_files()
        .into_iter()
        .flat_map(|file| global.decls_in(file).iter())
        .filter(|decl| decl.name == "run")
        .find_map(|decl| {
            decl.flow_events.iter().find_map(|event| match event {
                FlowEvent::Call { span, name, .. } if name == "execute" => {
                    Some((bonsai_common::FuncId::new(decl.symbol.raw()), *span))
                }
                _ => None,
            })
        })
        .expect("Repository.run execute call");
    let call_nodes = idg.nodes_at_span(repository_run, execute_span);
    let params = idg.param_nodes_of(execute);
    let sink_span = global
        .decl_of(bonsai_common::SymbolId::new(execute.raw()))
        .expect("execute declaration")
        .flow_events
        .iter()
        .find_map(|event| match event {
            FlowEvent::Call { span, name, .. } if name == "Process.runSync" => Some(*span),
            _ => None,
        })
        .expect("Process.runSync sink call");
    let sink_nodes = idg.nodes_at_span(execute, sink_span);

    assert!(
        call_nodes.iter().any(|source| {
            idg.resolve_point(*source)
                .is_some_and(|point| point.kind == PointKind::CallArg)
                && params.iter().any(|target| idg.reaches(*source, *target))
        }),
        "the resolved execute(c) call must stitch its AST CallArg to execute(cmd); call_nodes={:#?}; params={:#?}",
        call_nodes
            .iter()
            .filter_map(|node| idg.resolve_point(*node))
            .collect::<Vec<_>>(),
        params
            .iter()
            .filter_map(|node| idg.resolve_point(*node))
            .collect::<Vec<_>>()
    );
    assert!(
        params
            .iter()
            .any(|source| sink_nodes.iter().any(|target| idg.reaches(*source, *target))),
        "execute(cmd) must flow through the AST argument expression into Process.runSync; params={:#?}; sink_nodes={:#?}",
        params
            .iter()
            .filter_map(|node| idg.resolve_point(*node))
            .collect::<Vec<_>>(),
        sink_nodes
            .iter()
            .filter_map(|node| idg.resolve_point(*node))
            .collect::<Vec<_>>()
    );
}

#[test]
fn dart_mega_flow_security_source_reaches_process_sink() {
    let report = run_taint_analysis(
        &index_real_fixture("dart", "mega_flow"),
        &bonsai_security::load_rulepack(&rules_root()).expect("rulepack loads"),
        TaintAnalysisOptions {
            include_inferred_sources: true,
            ..Default::default()
        },
    )
    .expect("Dart mega-flow taint analysis");

    assert_eq!(
        report.findings.len(),
        1,
        "stdin.readLineSync must reach Process.runSync through the scoped semantic IDG: {:#?}",
        report.findings
    );
}

#[test]
fn mega_flow_taint_output_does_not_surface_known_overclaims() {
    let pack = bonsai_security::load_rulepack(&rules_root()).expect("rulepack loads");

    let c_report = run_taint_analysis(
        &index_real_fixture("c", "mega_flow"),
        &pack,
        TaintAnalysisOptions::default(),
    )
    .expect("c taint analysis");
    assert!(
        c_report
            .findings
            .iter()
            .all(|finding| !finding.finding.source.rule_id.starts_with("pattern:")),
        "default taint-analysis must not emit pattern-only findings: {:#?}",
        c_report.findings
    );
    assert!(
        c_report.findings.iter().all(|finding| {
            !matches!(
                finding.finding.sink.rule_id.as_str(),
                "c.memory.strncpy" | "c.memory.strncat"
            )
        }),
        "disabled context-dependent C memory rules must not report as taint findings: {:#?}",
        c_report.findings
    );
    let c_cmd = c_report
        .findings
        .iter()
        .find(|finding| finding.finding.sink.rule_id == "c.cmdi.system")
        .expect("c command-injection flow");
    assert_eq!(c_cmd.finding.source.rule_id, "c.input.argv_param");
    assert_eq!(
        c_cmd.finding.chain_display,
        ["main", "orchestrate", "persist", "run", "execute"],
        "{c_cmd:#?}"
    );
    assert!(
        c_cmd
            .finding
            .sanitizers_seen
            .iter()
            .all(|sanitizer| sanitizer.tag.as_deref() == Some("passthrough-transform")),
        "C strncpy transfer is configured passthrough semantics, not sanitizer credit: {c_cmd:#?}"
    );

    let python_report = run_taint_analysis(
        &index_real_fixture("python", "mega_flow"),
        &pack,
        TaintAnalysisOptions::default(),
    )
    .expect("python taint analysis");
    assert!(
        python_report
            .findings
            .iter()
            .all(|finding| finding.finding.sink.rule_id != "python.info_disclosure.flask_jsonify_exception"),
        "ordinary jsonify responses must not match the exception-disclosure sink: {:#?}",
        python_report.findings
    );
    let py_cmd = python_report
        .findings
        .iter()
        .find(|finding| finding.finding.sink.rule_id == "python.cmdi.os_system")
        .expect("python command-injection flow");
    assert_eq!(py_cmd.finding.source.line, 29, "{py_cmd:#?}");
    assert!(
        py_cmd.additional_sources.is_empty(),
        "sibling request fields must not be rendered as proven additional sources: {py_cmd:#?}"
    );
    let python_header_report = run_taint_analysis(
        &index_real_fixture("python", "mega_flow"),
        &pack,
        TaintAnalysisOptions {
            source: Some("python.web.request_headers_get".to_string()),
            ..TaintAnalysisOptions::default()
        },
    )
    .expect("python header-filtered taint analysis");
    assert!(
        python_header_report
            .findings
            .iter()
            .all(|finding| finding.finding.sink.rule_id != "python.cmdi.os_system"),
        "header/user taint must not be promoted into the command field: {:#?}",
        python_header_report.findings
    );

    let go_report = run_taint_analysis(
        &index_real_fixture("go", "mega_flow"),
        &pack,
        TaintAnalysisOptions::default(),
    )
    .expect("go taint analysis");
    let go_cmd = go_report
        .findings
        .iter()
        .find(|finding| finding.finding.sink.rule_id == "go.cmdi.exec_command_shell_wrapper")
        .expect("go command-injection flow");
    assert_eq!(go_cmd.finding.source.rule_id, "go.nethttp.query_value_get");
    assert_eq!(go_cmd.finding.source.line, 33, "{go_cmd:#?}");
    assert!(
        go_cmd.additional_sources.is_empty(),
        "header source must not be rendered as a proven source for env.Cmd flow: {go_cmd:#?}"
    );
    let go_header_report = run_taint_analysis(
        &index_real_fixture("go", "mega_flow"),
        &pack,
        TaintAnalysisOptions {
            source: Some("go.nethttp.header_get".to_string()),
            ..TaintAnalysisOptions::default()
        },
    )
    .expect("go header-filtered taint analysis");
    assert!(
        go_header_report
            .findings
            .iter()
            .all(|finding| finding.finding.sink.rule_id != "go.cmdi.exec_command_shell_wrapper"),
        "header source must not be promoted into env.Cmd command flow: {:#?}",
        go_header_report.findings
    );
}

#[test]
fn python_package_gate_uses_workspace_imports_for_local_db_wrapper_sinks() {
    let pack = bonsai_security::load_rulepack(&rules_root()).expect("rulepack loads");
    let ws = workspace(&[
        (
            "/app/api.py",
            r#"
from flask import request
from raw import string_agg

def aggregate():
    body = request.get_json(force=True, silent=True) or {}
    delimiter = body.get("delimiter", ",")
    return string_agg(delimiter)
"#,
        ),
        (
            "/app/raw.py",
            r#"
def string_agg(delimiter):
    sql = "SELECT STRING_AGG(name, '" + delimiter + "') FROM reports"
    cur = engine.connect().cursor()
    return cur.execute(sql)
"#,
        ),
        (
            "/app/engine.py",
            r#"
import psycopg2

engine = psycopg2.connect("")
"#,
        ),
    ]);

    let report = run_taint_analysis(&ws, &pack, TaintAnalysisOptions::default()).expect("taint analysis");
    assert!(
        report
            .findings
            .iter()
            .any(|finding| finding.finding.sink.rule_id == "python.sqli.cursor_execute"),
        "workspace-wide psycopg2 import evidence should gate the raw.py cursor.execute sink: {:#?}",
        report.findings
    );
}

#[test]
fn python_structured_safety_proofs_distinguish_guarded_and_unguarded_flows() {
    let mut pack = bonsai_security::load_rulepack(&rules_root()).expect("rulepack loads");
    let python = pack.packs.get_mut("python").expect("python pack");
    let mut fixture_source = rule(
        "python",
        RuleKind::Source,
        "python.test.compiler_fact_source",
        Some(TrustClass::Remote),
        None,
        "source",
    );
    fixture_source.tag = Some("remote-input".to_string());
    python.sources.push(fixture_source);

    let root = temp_real_workspace("structured-safety-proofs");
    std::fs::write(
        root.join("a_decoy.py"),
        r#"
def decoy_one():
    return 1

def decoy_two():
    return 2

def decoy_three():
    return 3
"#,
    )
    .expect("write symbol-id collision fixture");
    let fixture = root.join("guards.py");
    std::fs::write(
        &fixture,
        r#"
import os
import pymongo
import requests
import sqlite3
from jinja2 import Environment
from jinja2.sandbox import SandboxedEnvironment
from lxml import etree

_SAFE_PARSER = etree.XMLParser(
    resolve_entities=False,
    no_network=True,
    load_dtd=False,
)
_PARTIAL_PARSER = etree.XMLParser(resolve_entities=False)
_VALID_COLUMNS = {"amount", "quantity"}
_SORTABLE_COLUMNS = {"id": "id", "email": "email", "role": "role"}
_BASE = "/srv/files"

def source():
    return ""

def safe_http(provider):
    providers = {
        "a": "https://a.example/health",
        "b": "https://b.example/health",
    }
    selected = providers.get(provider, providers["a"])
    return requests.get(selected)

def safe_http_entry():
    return safe_http(source())

def unsafe_http(url):
    return requests.get(url)

def unsafe_http_entry():
    return unsafe_http(source())

def safe_xml(blob):
    return etree.fromstring(blob, parser=_SAFE_PARSER)

def safe_xml_entry():
    return safe_xml(source())

def safe_xml_positional(blob):
    return etree.fromstring(blob, _SAFE_PARSER)

def safe_xml_positional_entry():
    return safe_xml_positional(source())

def partial_xml(blob):
    return etree.fromstring(blob, parser=_PARTIAL_PARSER)

def partial_xml_entry():
    return partial_xml(source())

def overwritten_xml(blob):
    parser = etree.XMLParser(resolve_entities=False, no_network=True)
    parser = etree.XMLParser(resolve_entities=False)
    return etree.fromstring(blob, parser=parser)

def overwritten_xml_entry():
    return overwritten_xml(source())

def unsafe_xml(blob):
    return etree.fromstring(blob)

def unsafe_xml_entry():
    return unsafe_xml(source())

def safe_template(template_text):
    env = SandboxedEnvironment(autoescape=True)
    return env.from_string(template_text)

def safe_template_entry():
    return safe_template(source())

def unsafe_template(template_text):
    return Environment.from_string(template_text)

def unsafe_template_entry():
    return unsafe_template(source())

def safe_nosql(email):
    return pymongo.collection.find_one({"email": {"$eq": email}})

def safe_nosql_entry():
    return safe_nosql(source())

def safe_nosql_type_guard(email, password):
    if not isinstance(email, str) or not isinstance(password, str):
        raise ValueError("credentials must be strings")
    return pymongo.collection.find_one({"email": email, "password": password})

def safe_nosql_type_guard_entry():
    return safe_nosql_type_guard(source(), source())

def unsafe_nosql_inverted_guard(email, password):
    if isinstance(email, str) or isinstance(password, str):
        raise ValueError("inverted guard")
    return pymongo.collection.find_one({"email": email, "password": password})

def unsafe_nosql_inverted_guard_entry():
    return unsafe_nosql_inverted_guard(source(), source())

def unsafe_nosql_guarded_then_reassigned(email, password):
    if not isinstance(email, str) or not isinstance(password, str):
        raise ValueError("credentials must be strings")
    email = source()
    return pymongo.collection.find_one({"email": email, "password": password})

def unsafe_nosql_guarded_then_reassigned_entry():
    return unsafe_nosql_guarded_then_reassigned(source(), source())

def unsafe_nosql(email):
    return pymongo.collection.find_one({"email": email})

def unsafe_nosql_entry():
    return unsafe_nosql(source())

def safe_query(column, tenant):
    if column not in _VALID_COLUMNS:
        return []
    sql = "SELECT " + column + " FROM reports WHERE tenant_id = %s"
    params = (tenant,)
    return cursor.execute(sql, params)

def safe_query_entry():
    return safe_query(source(), source())

def safe_query_literal_map(column):
    selected = _SORTABLE_COLUMNS.get(column, "id")
    sql = f"SELECT * FROM reports ORDER BY {selected}"
    return cursor.execute(sql)

def safe_query_literal_map_entry():
    return safe_query_literal_map(source())

def unsafe_query(value):
    sql = "SELECT * FROM reports WHERE tenant_id = '" + value + "'"
    return cursor.execute(sql)

def unsafe_query_entry():
    return unsafe_query(source())

def safe_path(name):
    base_real = os.path.realpath(_BASE)
    candidate = os.path.realpath(os.path.join(base_real, name))
    if not candidate.startswith(base_real + os.sep):
        raise FileNotFoundError(candidate)
    return open(candidate, "rb")

def safe_path_entry():
    return safe_path(source())

def unsafe_path(name):
    return open(os.path.join(_BASE, name), "rb")

def unsafe_path_entry():
    return unsafe_path(source())
"#,
    )
    .expect("write structured safety fixture");
    let ws = Workspace::index(&root, bonsai_adapters::all_languages_registry())
        .expect("index structured safety fixture");

    let report = run_taint_analysis(
        &ws,
        &pack,
        TaintAnalysisOptions {
            show_sanitized: true,
            ..TaintAnalysisOptions::default()
        },
    )
    .expect("taint analysis");
    let finding_for = |function: &str, sink_rule: &str| {
        report
            .findings
            .iter()
            .find(|finding| {
                finding.finding.sink.enclosing_fn.as_deref() == Some(function)
                    && finding.finding.sink.rule_id == sink_rule
            })
            .unwrap_or_else(|| {
                panic!(
                    "missing {sink_rule} finding in {function}; findings={:#?}",
                    report.findings
                )
            })
    };

    for (safe_fn, unsafe_fn, safe_sink_rule, unsafe_sink_rule, sanitizer_rule) in [
        (
            "safe_http",
            "unsafe_http",
            "python.ssrf.requests_get",
            "python.ssrf.requests_get",
            "engine.sanitizer.literal_map_value_allowlist",
        ),
        (
            "safe_xml",
            "unsafe_xml",
            "python.xxe.lxml_fromstring",
            "python.xxe.lxml_fromstring",
            "engine.sanitizer.configured_argument_factory_guard",
        ),
        (
            "safe_template",
            "unsafe_template",
            "python.template.jinja2_env_from_string_instance",
            "python.template.jinja2_environment_from_string",
            "python.sanitizer.jinja2_sandboxed_from_string",
        ),
        (
            "safe_query",
            "unsafe_query",
            "python.sqli.cursor_execute",
            "python.sqli.cursor_execute",
            "engine.sanitizer.parameterized_query_allowlisted_fragments",
        ),
        (
            "safe_query_literal_map",
            "unsafe_query",
            "python.sqli.cursor_execute",
            "python.sqli.cursor_execute",
            "engine.sanitizer.literal_map_value_allowlist",
        ),
        (
            "safe_nosql",
            "unsafe_nosql",
            "python.nosql.pymongo_find_one",
            "python.nosql.pymongo_find_one",
            "engine.sanitizer.nosql_literal_operator_filter",
        ),
        (
            "safe_nosql_type_guard",
            "unsafe_nosql_inverted_guard",
            "python.nosql.pymongo_find_one",
            "python.nosql.pymongo_find_one",
            "python.sanitizer.isinstance_str_nosql_operator_guard",
        ),
        (
            "safe_path",
            "unsafe_path",
            "python.path.open",
            "python.path.open",
            "engine.sanitizer.path_consumer_containment_guard",
        ),
    ] {
        let safe = &finding_for(safe_fn, safe_sink_rule).finding;
        assert_eq!(safe.status, FindingStatus::Sanitized, "{safe:#?}");
        assert!(
            safe.sanitizers_seen
                .iter()
                .any(|sanitizer| sanitizer.rule_id == sanitizer_rule),
            "{safe_fn} must carry {sanitizer_rule} compiler-fact evidence: {safe:#?}"
        );

        let unsafe_finding = &finding_for(unsafe_fn, unsafe_sink_rule).finding;
        assert_eq!(
            unsafe_finding.status,
            FindingStatus::Unsanitized,
            "unguarded twin must remain reportable: {unsafe_finding:#?}"
        );
    }
    {
        let safe_fn = "safe_xml_positional";
        let safe = &finding_for(safe_fn, "python.xxe.lxml_fromstring").finding;
        assert_eq!(safe.status, FindingStatus::Sanitized, "{safe:#?}");
        assert!(
            safe.sanitizers_seen.iter().any(|sanitizer| {
                sanitizer.rule_id == "engine.sanitizer.configured_argument_factory_guard"
            }),
            "{safe_fn} must use the same typed configured-factory proof: {safe:#?}"
        );
    }
    {
        let unsafe_fn = "partial_xml";
        let unsafe_finding = &finding_for(unsafe_fn, "python.xxe.lxml_fromstring").finding;
        assert_eq!(
            unsafe_finding.status,
            FindingStatus::Unsanitized,
            "{unsafe_fn} must fail closed when the latest factory call lacks a required option: {unsafe_finding:#?}"
        );
    }
    let overwritten = &finding_for("overwritten_xml", "python.xxe.lxml_fromstring").finding;
    assert!(
        !overwritten
            .sanitizers_seen
            .iter()
            .any(|sanitizer| { sanitizer.rule_id == "engine.sanitizer.configured_argument_factory_guard" }),
        "the generic configured-factory proof must reject a weaker latest overwrite: {overwritten:#?}"
    );
    let reassigned = &finding_for(
        "unsafe_nosql_guarded_then_reassigned",
        "python.nosql.pymongo_find_one",
    )
    .finding;
    assert_eq!(
        reassigned.status,
        FindingStatus::Unsanitized,
        "a value replaced after the terminal type guard must remain reportable: {reassigned:#?}"
    );
    drop(ws);
    std::fs::remove_dir_all(&root).expect("remove structured safety fixture");
}

#[test]
fn typescript_dotted_local_model_import_carries_mongoose_package_evidence() {
    let pack = bonsai_security::load_rulepack(&rules_root()).expect("rulepack loads");
    let ws = workspace(&[
        (
            "/src/auth/auth.controller.ts",
            r#"
import { Body, Controller, Post } from "@nestjs/common";
import { AuthService } from "./auth.service";

@Controller("auth")
export class AuthController {
  constructor(private readonly auth: AuthService) {}

  @Post("login")
  async login(@Body() body: any) {
    return this.auth.findCreds(body);
  }
}
"#,
        ),
        (
            "/src/auth/auth.service.ts",
            r#"
import { UserModel } from "../user/user.model";

export class AuthService {
  async findCreds(body: any) {
    return UserModel.findOne({ email: body.email, password: body.password });
  }
}
"#,
        ),
        (
            "/src/user/user.model.ts",
            r#"
import mongoose from "mongoose";

const Schema = new mongoose.Schema({ email: String, password: String });
export const UserModel = mongoose.model("User", Schema);
"#,
        ),
    ]);

    let report = run_taint_analysis(&ws, &pack, TaintAnalysisOptions::default()).expect("taint analysis");
    assert!(
        report
            .findings
            .iter()
            .any(|finding| finding.finding.sink.rule_id == "typescript.nosql.mongo_find"),
        "relative import `../user/user.model` should resolve to user.model.ts and carry mongoose evidence: {:#?}",
        report.findings
    );
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

#[test]
fn nested_call_argument_uses_callee_return_summary_for_sink_taint() {
    let ws = workspace(&[
        (
            "/app/server.js",
            "import { renderUnsafe } from './render.js';\n\
             function source() { return ''; }\n\
             export function handle(res) {\n  const q = source();\n  res.end(renderUnsafe(q));\n}\n",
        ),
        (
            "/app/render.js",
            "export function renderUnsafe(q) {\n  return '<p>' + q + '</p>';\n}\n",
        ),
    ]);
    let report = run_taint_analysis(
        &ws,
        &constrained_call_sink_rulepack("javascript", "source", "res.end"),
        TaintAnalysisOptions::default(),
    )
    .expect("taint analysis");

    assert!(
        report.findings.iter().any(|finding| {
            finding.finding.sink.file.contains("server.js")
                && finding.finding.sink.text == "res.end"
                && finding.finding.chain_display == ["handle"]
        }),
        "expected nested call return taint to reach res.end, got {:#?}",
        report.findings
    );
}

#[test]
fn nested_call_argument_clean_return_does_not_taint_outer_sink() {
    let ws = workspace(&[
        (
            "/app/server.js",
            "import { renderSafe } from './render.js';\n\
             function source() { return ''; }\n\
             export function handle(res) {\n  const q = source();\n  res.end(renderSafe(q));\n}\n",
        ),
        (
            "/app/render.js",
            "export function renderSafe(q) {\n  return '<p>safe</p>';\n}\n",
        ),
    ]);
    let report = run_taint_analysis(
        &ws,
        &constrained_call_sink_rulepack("javascript", "source", "res.end"),
        TaintAnalysisOptions::default(),
    )
    .expect("taint analysis");

    assert!(
        report.findings.is_empty(),
        "constant-return helper must not taint outer sink just because the argument syntax mentions q: {:#?}",
        report.findings
    );
}

#[test]
fn sanitizer_wrapping_source_attaches_to_same_function_flow() {
    let ws = workspace(&[(
        "/app/App.java",
        "import org.owasp.esapi.ESAPI;\n\n\
         class App {\n  static String source() { return \"\"; }\n  static void sink(String value) {}\n\n\
         void handle() {\n    String clean = ESAPI.encoder().encodeForHTML(source());\n    sink(clean);\n  }\n}\n",
    )]);
    let mut pack = rulepack("java", "source", "sink");
    let java_pack = pack.packs.get_mut("java").expect("java pack");
    java_pack.sinks[0].tag = Some("xss".to_string());
    java_pack.sanitizers.push(Rule {
        id: "java.test.esapi_html".to_string(),
        aliases: Vec::new(),
        enabled: true,
        disabled_reason: None,
        title: None,
        tag: Some("html-encode".to_string()),
        severity: None,
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
            kind: MatchKind::Call,
            callee: Some(RuleTarget {
                regex: Some(r"^(Encoder|ESAPI\.encoder\(\))\.encodeForHTML$".to_string()),
                ..Default::default()
            }),
            target: None,
            search_depth: 0,
        },
        analysis_semantics: None,
        taint_semantics: None,
        returns_type: None,
        constraints: RuleConstraint::default(),
        match_examples: Vec::new(),
        description: "test ESAPI sanitizer".to_string(),
        kind: RuleKind::Sanitizer,
        language: "java".to_string(),
        source_path: String::new(),
    });

    let report = run_taint_analysis(
        &ws,
        &pack,
        TaintAnalysisOptions {
            show_sanitized: true,
            ..TaintAnalysisOptions::default()
        },
    )
    .expect("taint analysis");
    assert_eq!(report.findings.len(), 1, "{:#?}", report.findings);
    let finding = &report.findings[0].finding;
    assert_eq!(finding.status, FindingStatus::Sanitized, "{finding:#?}");
    assert!(
        finding
            .sanitizers_seen
            .iter()
            .any(|sanitizer| sanitizer.rule_id == "java.test.esapi_html"),
        "expected ESAPI sanitizer evidence, got {:#?}",
        finding.sanitizers_seen
    );
}

#[test]
fn nested_fully_qualified_esapi_sanitizer_inside_sink_arg_attaches() {
    let ws = workspace(&[(
        "/app/App.java",
        "class App {\n  static String source() { return \"\"; }\n  static void sink(String value) {}\n\n\
         void handle() {\n    String input = source();\n    sink(\"Sensitive value '\" + org.owasp.esapi.ESAPI.encoder().encodeForHTML(input) + \"'\");\n  }\n}\n",
    )]);
    let mut pack = rulepack("java", "source", "sink");
    let java_pack = pack.packs.get_mut("java").expect("java pack");
    java_pack.sinks[0].tag = Some("xss".to_string());
    java_pack.sanitizers.push(Rule {
        id: "java.test.esapi_html_fqn".to_string(),
        aliases: Vec::new(),
        enabled: true,
        disabled_reason: None,
        title: None,
        tag: Some("html-encode".to_string()),
        severity: None,
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
            kind: MatchKind::Call,
            callee: Some(RuleTarget {
                regex: Some(
                    r"^(?:org\.owasp\.esapi\.)?(?:Encoder|ESAPI\.encoder\(\))\.encodeForHTML$".to_string(),
                ),
                ..Default::default()
            }),
            target: None,
            search_depth: 0,
        },
        analysis_semantics: None,
        taint_semantics: Some(TaintSemantics {
            clean_output_overwrite: None,
            source_output_args: Vec::new(),
            source_callback_args: Vec::new(),
            call_result_passthrough_args: vec![0],
            call_result_passthrough_receiver: false,
            output_arg_flows: Vec::new(),
            taint_receiver_from_args: false,
        }),
        returns_type: None,
        constraints: RuleConstraint::default(),
        match_examples: Vec::new(),
        description: "test fully qualified ESAPI sanitizer".to_string(),
        kind: RuleKind::Sanitizer,
        language: "java".to_string(),
        source_path: String::new(),
    });

    let report = run_taint_analysis(
        &ws,
        &pack,
        TaintAnalysisOptions {
            show_sanitized: true,
            ..TaintAnalysisOptions::default()
        },
    )
    .expect("taint analysis");
    assert_eq!(report.findings.len(), 1, "{:#?}", report.findings);
    let finding = &report.findings[0].finding;
    assert_eq!(finding.status, FindingStatus::Sanitized, "{finding:#?}");
    assert!(
        finding
            .sanitizers_seen
            .iter()
            .any(|sanitizer| sanitizer.rule_id == "java.test.esapi_html_fqn"),
        "expected FQN ESAPI sanitizer evidence, got {:#?}",
        finding.sanitizers_seen
    );
}

#[test]
fn sanitizer_in_helper_return_attaches_after_chain_display_collapse() {
    let ws = workspace(&[(
        "/app/App.java",
        "class App {\n  static String source() { return \"\"; }\n  static void sink(String value) {}\n\n\
         void handle() {\n    String input = source();\n    String clean = escape(input);\n    sink(clean);\n  }\n\n\
         static String escape(String value) {\n    String out = org.owasp.esapi.ESAPI.encoder().encodeForHTML(value);\n    return out;\n  }\n}\n",
    )]);
    let mut pack = rulepack("java", "source", "sink");
    let java_pack = pack.packs.get_mut("java").expect("java pack");
    java_pack.sinks[0].tag = Some("xss".to_string());
    java_pack.sanitizers.push(Rule {
        id: "java.test.esapi_html_helper_return".to_string(),
        aliases: Vec::new(),
        enabled: true,
        disabled_reason: None,
        title: None,
        tag: Some("html-encode".to_string()),
        severity: None,
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
            kind: MatchKind::Call,
            callee: Some(RuleTarget {
                regex: Some(
                    r"^(?:org\.owasp\.esapi\.)?(?:Encoder|ESAPI\.encoder\(\))\.encodeForHTML$".to_string(),
                ),
                ..Default::default()
            }),
            target: None,
            search_depth: 0,
        },
        analysis_semantics: None,
        taint_semantics: Some(TaintSemantics {
            clean_output_overwrite: None,
            source_output_args: Vec::new(),
            source_callback_args: Vec::new(),
            call_result_passthrough_args: vec![0],
            call_result_passthrough_receiver: false,
            output_arg_flows: Vec::new(),
            taint_receiver_from_args: false,
        }),
        returns_type: None,
        constraints: RuleConstraint::default(),
        match_examples: Vec::new(),
        description: "test ESAPI sanitizer in helper return".to_string(),
        kind: RuleKind::Sanitizer,
        language: "java".to_string(),
        source_path: String::new(),
    });

    let report = run_taint_analysis(
        &ws,
        &pack,
        TaintAnalysisOptions {
            show_sanitized: true,
            ..TaintAnalysisOptions::default()
        },
    )
    .expect("taint analysis");
    assert_eq!(report.findings.len(), 1, "{:#?}", report.findings);
    let finding = &report.findings[0].finding;
    assert_eq!(finding.status, FindingStatus::Sanitized, "{finding:#?}");
    assert!(
        finding
            .sanitizers_seen
            .iter()
            .any(|sanitizer| sanitizer.rule_id == "engine.sanitizer.java_local_html_escape_helper_return"),
        "expected helper-return ESAPI sanitizer evidence, got {:#?}",
        finding.sanitizers_seen
    );
}

#[test]
fn sanitized_flows_are_hidden_by_default_and_visible_on_request() {
    let ws = workspace(&[(
        "/app/App.java",
        "import org.owasp.esapi.ESAPI;\n\n\
         class App {\n  static String source() { return \"\"; }\n  static void sink(String value) {}\n\n\
         void handle() {\n    String clean = ESAPI.encoder().encodeForHTML(source());\n    sink(clean);\n  }\n}\n",
    )]);
    let mut pack = rulepack("java", "source", "sink");
    let java_pack = pack.packs.get_mut("java").expect("java pack");
    java_pack.sinks[0].tag = Some("xss".to_string());
    java_pack.sanitizers.push(Rule {
        id: "java.test.esapi_html".to_string(),
        aliases: Vec::new(),
        enabled: true,
        disabled_reason: None,
        title: None,
        tag: Some("html-encode".to_string()),
        severity: None,
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
            kind: MatchKind::Call,
            callee: Some(RuleTarget {
                regex: Some(r"^(Encoder|ESAPI\.encoder\(\))\.encodeForHTML$".to_string()),
                ..Default::default()
            }),
            target: None,
            search_depth: 0,
        },
        analysis_semantics: None,
        taint_semantics: None,
        returns_type: None,
        constraints: RuleConstraint::default(),
        match_examples: Vec::new(),
        description: "test ESAPI sanitizer".to_string(),
        kind: RuleKind::Sanitizer,
        language: "java".to_string(),
        source_path: String::new(),
    });

    let default_report =
        run_taint_analysis(&ws, &pack, TaintAnalysisOptions::default()).expect("taint analysis");
    assert!(
        default_report.findings.is_empty(),
        "sanitized findings should be suppressed unless requested: {:#?}",
        default_report.findings
    );

    let explicit_report = run_taint_analysis(
        &ws,
        &pack,
        TaintAnalysisOptions {
            show_sanitized: true,
            ..TaintAnalysisOptions::default()
        },
    )
    .expect("taint analysis");
    assert_eq!(
        explicit_report.findings.len(),
        1,
        "{:#?}",
        explicit_report.findings
    );
    assert_eq!(
        explicit_report.findings[0].finding.status,
        FindingStatus::Sanitized,
        "{:#?}",
        explicit_report.findings
    );
}

#[test]
fn python_compiled_regex_guard_sanitizes_later_path_sink() {
    let mut pack = rulepack("python", "source", "os.path.join");
    let python_pack = pack.packs.get_mut("python").expect("python pack");
    python_pack.sinks[0].tag = Some("path-traversal".to_string());
    python_pack.sinks[0].constraints = RuleConstraint(vec![ConstraintKind::ArgTainted {
        arg_tainted: ArgTaintedSpec {
            index: Some(1),
            kw: None,
        },
    }]);

    let ws = workspace(&[(
        "/app/app.py",
        r#"
import os
import re

_NAME_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}\.(mp4|mkv|webm)$")

def source():
    return "user"

def handle():
    name = source()
    if not _NAME_RE.match(name):
        return
    return os.path.join("/srv/uploads", name)
"#,
    )]);
    let default_report =
        run_taint_analysis(&ws, &pack, TaintAnalysisOptions::default()).expect("taint analysis");
    assert!(
        default_report.findings.is_empty(),
        "safe compiled-regex guard should suppress sanitized path findings by default: {:#?}",
        default_report.findings
    );

    let explicit_report = run_taint_analysis(
        &ws,
        &pack,
        TaintAnalysisOptions {
            show_sanitized: true,
            ..TaintAnalysisOptions::default()
        },
    )
    .expect("taint analysis");
    assert_eq!(
        explicit_report.findings.len(),
        1,
        "{:#?}",
        explicit_report.findings
    );
    let finding = &explicit_report.findings[0].finding;
    assert_eq!(finding.status, FindingStatus::Sanitized, "{finding:#?}");
    assert!(
        finding
            .sanitizers_seen
            .iter()
            .any(|sanitizer| sanitizer.rule_id == "engine.sanitizer.python_compiled_regex_guard"),
        "expected compiled regex guard evidence, got {:#?}",
        finding.sanitizers_seen
    );

    let broad_ws = workspace(&[(
        "/app/app.py",
        r#"
import os
import re

_NAME_RE = re.compile(r"^.*$")

def source():
    return "user"

def handle():
    name = source()
    if not _NAME_RE.match(name):
        return
    return os.path.join("/srv/uploads", name)
"#,
    )]);
    let broad_report =
        run_taint_analysis(&broad_ws, &pack, TaintAnalysisOptions::default()).expect("taint analysis");
    assert_eq!(
        broad_report.findings.len(),
        1,
        "broad regex must not sanitize path traversal: {:#?}",
        broad_report.findings
    );
    assert_eq!(
        broad_report.findings[0].finding.status,
        FindingStatus::Unsanitized,
        "{:#?}",
        broad_report.findings
    );
}

#[test]
fn python_realpath_containment_branch_sanitizes_join_sink() {
    let mut pack = rulepack("python", "source", "os.path.join");
    let python_pack = pack.packs.get_mut("python").expect("python pack");
    python_pack.sinks[0].tag = Some("path-traversal".to_string());
    python_pack.sinks[0].analysis_semantics = Some(AnalysisSemantics {
        guard_profile: Some(GuardProfile::PythonPathContainment),
        path_containment_guard: Some(PathContainmentGuardSemantics {
            canonicalizer: RuleTarget {
                attribute: Some(vec!["os".to_string(), "path".to_string(), "realpath".to_string()]),
                ..RuleTarget::default()
            },
            containment_check: RuleTarget {
                name: Some("startswith".to_string()),
                ..RuleTarget::default()
            },
            sink_base_arg_index: 0,
            boundary_places: vec!["os.sep".to_string()],
        }),
        ..AnalysisSemantics::default()
    });
    python_pack.sinks[0].constraints = RuleConstraint(vec![ConstraintKind::ArgTainted {
        arg_tainted: ArgTaintedSpec {
            index: Some(1),
            kw: None,
        },
    }]);

    let ws = workspace(&[(
        "/app/app.py",
        r#"
import os

def source():
    return "user"

def handle():
    base = "/srv/uploads"
    name = source()
    candidate = os.path.realpath(os.path.join(base, name))
    if not candidate.startswith(base + os.sep):
        raise PermissionError("outside upload root")
    return candidate
"#,
    )]);

    let default_report =
        run_taint_analysis(&ws, &pack, TaintAnalysisOptions::default()).expect("taint analysis");
    assert!(
        default_report.findings.is_empty(),
        "realpath containment branch should suppress the guarded join: {:#?}",
        default_report.findings
    );

    let explicit_report = run_taint_analysis(
        &ws,
        &pack,
        TaintAnalysisOptions {
            show_sanitized: true,
            ..TaintAnalysisOptions::default()
        },
    )
    .expect("taint analysis");
    assert_eq!(
        explicit_report.findings.len(),
        1,
        "{:#?}",
        explicit_report.findings
    );
    let finding = &explicit_report.findings[0].finding;
    assert_eq!(finding.status, FindingStatus::Sanitized, "{finding:#?}");
    assert!(
        finding
            .sanitizers_seen
            .iter()
            .any(|sanitizer| sanitizer.rule_id == "engine.sanitizer.path_containment_guard"),
        "expected realpath containment guard evidence, got {:#?}",
        finding.sanitizers_seen
    );

    let mut mismatched_pack = pack.clone();
    mismatched_pack
        .packs
        .get_mut("python")
        .and_then(|pack| pack.sinks.first_mut())
        .and_then(|rule| rule.analysis_semantics.as_mut())
        .and_then(|semantics| semantics.path_containment_guard.as_mut())
        .expect("configured path containment semantics")
        .boundary_places = vec!["path.separator".to_string()];
    let mismatched_report =
        run_taint_analysis(&ws, &mismatched_pack, TaintAnalysisOptions::default()).expect("taint analysis");
    assert!(
        mismatched_report.findings.iter().any(|finding| {
            finding.finding.sink.rule_id == "python.test.sink"
                && finding.finding.status == FindingStatus::Unsanitized
        }),
        "the proof must be driven by rulepack boundary operands: {:#?}",
        mismatched_report.findings
    );

    let double_negated_ws = workspace(&[(
        "/app/app.py",
        r#"
import os

def source():
    return "user"

def handle():
    base = "/srv/uploads"
    name = source()
    candidate = os.path.realpath(os.path.join(base, name))
    if not not candidate.startswith(base + os.sep):
        raise PermissionError("inverted guard")
    return candidate
"#,
    )]);
    let double_negated_report =
        run_taint_analysis(&double_negated_ws, &pack, TaintAnalysisOptions::default())
            .expect("taint analysis");
    assert!(
        double_negated_report.findings.iter().any(|finding| {
            finding.finding.sink.rule_id == "python.test.sink"
                && finding.finding.status == FindingStatus::Unsanitized
        }),
        "an even number of AST negations must not prove a rejection guard: {:#?}",
        double_negated_report.findings
    );

    let exact_base_or_contained_ws = workspace(&[(
        "/app/app.py",
        r#"
import os

def source():
    return "user"

def handle():
    base = os.path.realpath("/srv/uploads")
    name = source()
    candidate = os.path.realpath(os.path.join(base, name))
    if candidate != base and not candidate.startswith(base + os.sep):
        raise PermissionError("outside upload root")
    return candidate
"#,
    )]);
    let exact_base_or_contained_report = run_taint_analysis(
        &exact_base_or_contained_ws,
        &pack,
        TaintAnalysisOptions::default(),
    )
    .expect("taint analysis");
    assert!(
        exact_base_or_contained_report.findings.is_empty(),
        "the typed base-equality-or-containment rejection must sanitize: {:#?}",
        exact_base_or_contained_report.findings
    );

    let inverted_compound_ws = workspace(&[(
        "/app/app.py",
        r#"
import os

def source():
    return "user"

def handle():
    base = os.path.realpath("/srv/uploads")
    name = source()
    candidate = os.path.realpath(os.path.join(base, name))
    if candidate != base and candidate.startswith(base + os.sep):
        raise PermissionError("rejects the safe path")
    return candidate
"#,
    )]);
    let inverted_compound_report =
        run_taint_analysis(&inverted_compound_ws, &pack, TaintAnalysisOptions::default())
            .expect("taint analysis");
    assert!(
        inverted_compound_report.findings.iter().any(|finding| {
            finding.finding.sink.rule_id == "python.test.sink"
                && finding.finding.status == FindingStatus::Unsanitized
        }),
        "an inverted compound guard must remain vulnerable: {:#?}",
        inverted_compound_report.findings
    );
}

#[test]
fn direct_parser_configuration_requires_complete_typed_aggregate() {
    let mut pack = rulepack("javascript", "source", "parseXml");
    let sink = pack
        .packs
        .get_mut("javascript")
        .and_then(|pack| pack.sinks.first_mut())
        .expect("JavaScript sink");
    sink.tag = Some("xxe".to_string());
    sink.constraints = RuleConstraint(vec![ConstraintKind::ArgTainted {
        arg_tainted: ArgTaintedSpec {
            index: Some(0),
            kw: None,
        },
    }]);
    sink.analysis_semantics = Some(AnalysisSemantics {
        configured_call_argument_guard: Some(ConfiguredCallArgumentGuardSemantics {
            configuration_argument_index: 1,
            guarded_value_argument_indices: vec![0],
            required_fields: vec![
                RequiredAggregateFieldSemantics {
                    path: vec!["noent".to_string()],
                    value: StaticScalarValue::Boolean(false),
                },
                RequiredAggregateFieldSemantics {
                    path: vec!["replaceEntities".to_string()],
                    value: StaticScalarValue::Boolean(false),
                },
                RequiredAggregateFieldSemantics {
                    path: vec!["nonet".to_string()],
                    value: StaticScalarValue::Boolean(true),
                },
                RequiredAggregateFieldSemantics {
                    path: vec!["dtdload".to_string()],
                    value: StaticScalarValue::Boolean(false),
                },
            ],
        }),
        ..AnalysisSemantics::default()
    });
    let ws = workspace(&[(
        "/app/parser.js",
        r#"
function source() { return ""; }
function safe() {
  return parseXml(source(), {
    noent: false,
    replaceEntities: false,
    nonet: true,
    dtdload: false,
  });
}

function partial() {
  return parseXml(source(), {
    noent: false,
    replaceEntities: false,
    nonet: true,
  });
}

function spread(defaults) {
  return parseXml(source(), {
    ...defaults,
    noent: false,
    replaceEntities: false,
    nonet: true,
    dtdload: false,
  });
}
"#,
    )]);
    let report = run_taint_analysis(
        &ws,
        &pack,
        TaintAnalysisOptions {
            show_sanitized: true,
            ..TaintAnalysisOptions::default()
        },
    )
    .expect("taint analysis");
    let finding = |function: &str| {
        &report
            .findings
            .iter()
            .find(|finding| finding.finding.sink.enclosing_fn.as_deref() == Some(function))
            .unwrap_or_else(|| panic!("missing {function}: {:#?}", report.findings))
            .finding
    };
    assert_eq!(finding("safe").status, FindingStatus::Sanitized);
    assert!(finding("safe")
        .sanitizers_seen
        .iter()
        .any(|sanitizer| { sanitizer.rule_id == "engine.sanitizer.configured_call_argument_guard" }));
    assert_eq!(finding("partial").status, FindingStatus::Unsanitized);
    assert_eq!(finding("spread").status, FindingStatus::Unsanitized);
}

#[test]
fn receiver_configuration_requires_unconditional_complete_constructor_state() {
    let mut pack = constrained_call_sink_rulepack("java", "source", "fromXML");
    let sink = pack
        .packs
        .get_mut("java")
        .and_then(|pack| pack.sinks.first_mut())
        .expect("Java sink");
    sink.tag = Some("insecure-deserialization".to_string());
    sink.analysis_semantics = Some(AnalysisSemantics {
        receiver_configuration_guard: Some(ReceiverConfigurationGuardSemantics {
            required_calls: vec![
                RequiredReceiverCallSemantics {
                    call: RuleTarget {
                        name: Some("addPermission".to_string()),
                        ..RuleTarget::default()
                    },
                    identity_argument_indices: vec![0],
                    required_arguments: vec![RequiredCallArgumentSemantics {
                        index: 0,
                        require_static_value: false,
                        accepted_places: vec!["NoTypePermission.NONE".to_string()],
                        accepted_static_values: Vec::new(),
                    }],
                },
                RequiredReceiverCallSemantics {
                    call: RuleTarget {
                        name: Some("allowTypes".to_string()),
                        ..RuleTarget::default()
                    },
                    identity_argument_indices: Vec::new(),
                    required_arguments: Vec::new(),
                },
            ],
        }),
        ..AnalysisSemantics::default()
    });
    let ws = workspace(&[(
        "/app/Loaders.java",
        r#"
class NoTypePermission { static final Object NONE = new Object(); }
class NullPermission { static final Object NULL = new Object(); }
class PrimitiveTypePermission { static final Object PRIMITIVES = new Object(); }
class XStream {
  void addPermission(Object permission) {}
  void allowTypes(Object... types) {}
  Object fromXML(String xml) { return null; }
}
class Input { static String source() { return ""; } }
class SafeLoader {
  private final XStream xstream = new XStream();
  SafeLoader() {
    xstream.addPermission(NoTypePermission.NONE);
    xstream.addPermission(NullPermission.NULL);
    xstream.addPermission(PrimitiveTypePermission.PRIMITIVES);
    xstream.allowTypes(new Class[]{String.class});
  }
  Object safe() { return xstream.fromXML(Input.source()); }
}
class PartialLoader {
  private final XStream xstream = new XStream();
  PartialLoader() { xstream.addPermission(NoTypePermission.NONE); }
  Object partial() { return xstream.fromXML(Input.source()); }
}
class ConditionalLoader {
  private final XStream xstream = new XStream();
  ConditionalLoader(boolean enabled) {
    xstream.addPermission(NoTypePermission.NONE);
    if (enabled) xstream.allowTypes(new Class[]{String.class});
  }
  Object conditional() { return xstream.fromXML(Input.source()); }
}
class MutableLoader {
  private XStream xstream = new XStream();
  MutableLoader() {
    xstream.addPermission(NoTypePermission.NONE);
    xstream.allowTypes(new Class[]{String.class});
  }
  Object mutable() { return xstream.fromXML(Input.source()); }
}
class ReassignedLoader {
  Object reassigned() {
    XStream xstream = new XStream();
    xstream.addPermission(NoTypePermission.NONE);
    xstream.allowTypes(new Class[]{String.class});
    xstream = new XStream();
    return xstream.fromXML(Input.source());
  }
}
"#,
    )]);
    let report = run_taint_analysis(
        &ws,
        &pack,
        TaintAnalysisOptions {
            show_sanitized: true,
            ..TaintAnalysisOptions::default()
        },
    )
    .expect("taint analysis");
    let finding = |function: &str| {
        &report
            .findings
            .iter()
            .find(|finding| finding.finding.sink.enclosing_fn.as_deref() == Some(function))
            .unwrap_or_else(|| panic!("missing {function}: {:#?}", report.findings))
            .finding
    };
    assert_eq!(finding("safe").status, FindingStatus::Sanitized);
    assert!(finding("safe")
        .sanitizers_seen
        .iter()
        .any(|sanitizer| { sanitizer.rule_id == "engine.sanitizer.receiver_configuration_guard" }));
    assert_eq!(finding("partial").status, FindingStatus::Unsanitized);
    assert_eq!(finding("conditional").status, FindingStatus::Unsanitized);
    assert_eq!(finding("mutable").status, FindingStatus::Unsanitized);
    assert_eq!(finding("reassigned").status, FindingStatus::Unsanitized);
}

#[test]
fn receiver_factory_requires_every_declared_nested_factory() {
    let mut pack = constrained_call_sink_rulepack("java", "source", "load");
    let sink = pack
        .packs
        .get_mut("java")
        .and_then(|pack| pack.sinks.first_mut())
        .expect("Java sink");
    sink.tag = Some("insecure-deserialization".to_string());
    sink.analysis_semantics = Some(AnalysisSemantics {
        receiver_factory_guard: Some(ReceiverFactoryGuardSemantics {
            factories: vec![RuleTarget {
                name: Some("Yaml".to_string()),
                ..RuleTarget::default()
            }],
            required_nested_factories: vec![RuleTarget {
                name: Some("SafeConstructor".to_string()),
                ..RuleTarget::default()
            }],
        }),
        ..AnalysisSemantics::default()
    });
    let ws = workspace(&[(
        "/app/YamlLoader.java",
        r#"
class SafeConstructor {}
class UnsafeConstructor {}
class Yaml {
  Yaml(Object constructor) {}
  Object load(String yaml) { return null; }
}
class Input { static String source() { return ""; } }
class YamlLoader {
  Object safe() {
    Yaml yaml = new Yaml(new SafeConstructor());
    return yaml.load(Input.source());
  }
  Object unsafe() {
    Yaml yaml = new Yaml(new UnsafeConstructor());
    return yaml.load(Input.source());
  }
}
"#,
    )]);
    let report = run_taint_analysis(
        &ws,
        &pack,
        TaintAnalysisOptions {
            show_sanitized: true,
            ..TaintAnalysisOptions::default()
        },
    )
    .expect("taint analysis");
    let finding = |function: &str| {
        &report
            .findings
            .iter()
            .find(|finding| finding.finding.sink.enclosing_fn.as_deref() == Some(function))
            .unwrap_or_else(|| panic!("missing {function}: {:#?}", report.findings))
            .finding
    };
    assert_eq!(finding("safe").status, FindingStatus::Sanitized);
    assert!(finding("safe")
        .sanitizers_seen
        .iter()
        .any(|sanitizer| sanitizer.rule_id == "engine.sanitizer.receiver_factory_guard"));
    assert_eq!(finding("unsafe").status, FindingStatus::Unsanitized);
}

#[test]
fn configured_receiver_wrapper_requires_complete_prior_state() {
    let mut pack = constrained_call_sink_rulepack("java", "source", "unmarshal");
    let sink = pack
        .packs
        .get_mut("java")
        .and_then(|pack| pack.sinks.first_mut())
        .expect("Java sink");
    sink.tag = Some("xxe".to_string());
    let required_feature = |name: &str, enabled: bool| RequiredReceiverCallSemantics {
        call: RuleTarget {
            name: Some("setFeature".to_string()),
            ..RuleTarget::default()
        },
        identity_argument_indices: vec![0],
        required_arguments: vec![
            RequiredCallArgumentSemantics {
                index: 0,
                require_static_value: false,
                accepted_places: Vec::new(),
                accepted_static_values: vec![StaticScalarValue::String(name.to_string())],
            },
            RequiredCallArgumentSemantics {
                index: 1,
                require_static_value: false,
                accepted_places: Vec::new(),
                accepted_static_values: vec![StaticScalarValue::Boolean(enabled)],
            },
        ],
    };
    sink.analysis_semantics = Some(AnalysisSemantics {
        configured_argument_receiver_guard: Some(ConfiguredArgumentReceiverGuardSemantics {
            sink_argument_index: 0,
            wrapper_factory: RuleTarget {
                name: Some("SAXSource".to_string()),
                ..RuleTarget::default()
            },
            configured_receiver_argument_index: 0,
            provider_factory: RuleTarget {
                name: Some("newSAXParser".to_string()),
                ..RuleTarget::default()
            },
            required_calls: vec![
                required_feature("secure", true),
                required_feature("external-general", false),
            ],
        }),
        ..AnalysisSemantics::default()
    });
    let ws = workspace(&[(
        "/app/XmlLoader.java",
        r#"
class ParserFactory {
  void setFeature(String name, boolean value) {}
  Parser newSAXParser() { return new Parser(); }
}
class Parser { Object getXMLReader() { return null; } }
class SAXSource { SAXSource(Object reader, String xml) {} }
class Unmarshaller { Object unmarshal(SAXSource source) { return null; } }
class Input { static String source() { return ""; } }
class XmlLoader {
  Object safe() {
    ParserFactory factory = new ParserFactory();
    factory.setFeature("secure", true);
    factory.setFeature("external-general", false);
    SAXSource source = new SAXSource(factory.newSAXParser().getXMLReader(), Input.source());
    return new Unmarshaller().unmarshal(source);
  }
  Object partial() {
    ParserFactory factory = new ParserFactory();
    factory.setFeature("secure", true);
    SAXSource source = new SAXSource(factory.newSAXParser().getXMLReader(), Input.source());
    return new Unmarshaller().unmarshal(source);
  }
  Object conditional(boolean harden) {
    ParserFactory factory = new ParserFactory();
    factory.setFeature("secure", true);
    if (harden) factory.setFeature("external-general", false);
    SAXSource source = new SAXSource(factory.newSAXParser().getXMLReader(), Input.source());
    return new Unmarshaller().unmarshal(source);
  }
  Object overwritten() {
    ParserFactory factory = new ParserFactory();
    factory.setFeature("secure", true);
    factory.setFeature("external-general", false);
    factory.setFeature("secure", false);
    SAXSource source = new SAXSource(factory.newSAXParser().getXMLReader(), Input.source());
    return new Unmarshaller().unmarshal(source);
  }
}
"#,
    )]);
    let report = run_taint_analysis(
        &ws,
        &pack,
        TaintAnalysisOptions {
            show_sanitized: true,
            ..TaintAnalysisOptions::default()
        },
    )
    .expect("taint analysis");
    let finding = |function: &str| {
        &report
            .findings
            .iter()
            .find(|finding| finding.finding.sink.enclosing_fn.as_deref() == Some(function))
            .unwrap_or_else(|| panic!("missing {function}: {:#?}", report.findings))
            .finding
    };
    assert_eq!(finding("safe").status, FindingStatus::Sanitized);
    assert!(finding("safe")
        .sanitizers_seen
        .iter()
        .any(|sanitizer| { sanitizer.rule_id == "engine.sanitizer.configured_argument_receiver_guard" }));
    assert_eq!(finding("partial").status, FindingStatus::Unsanitized);
    assert_eq!(finding("conditional").status, FindingStatus::Unsanitized);
    assert_eq!(finding("overwritten").status, FindingStatus::Unsanitized);
}

#[test]
fn local_trust_caps_emitted_finding_severity() {
    let mut pack = rulepack("python", "source", "danger");
    let language = pack.packs.get_mut("python").expect("Python pack");
    language.sources[0].trust = Some(TrustClass::Local);
    language.sinks[0].severity = Some(Severity::Critical);
    let ws = workspace(&[(
        "/app/tool.py",
        r#"
def source():
    return "operator argument"

def danger(value):
    return value

def main():
    danger(source())
"#,
    )]);
    let report = run_taint_analysis(&ws, &pack, TaintAnalysisOptions::default()).expect("taint analysis");
    assert_eq!(report.findings.len(), 1, "{:#?}", report.findings);
    assert_eq!(
        report.findings[0].finding.severity,
        Some(Severity::Medium),
        "local operator input must not inherit network-grade severity: {:#?}",
        report.findings
    );
}

#[test]
fn comprehension_character_constraint_sanitizes_only_its_exact_lineage() {
    let mut pack = rulepack("python", "source", "cursor.execute");
    let sink = pack
        .packs
        .get_mut("python")
        .and_then(|pack| pack.sinks.first_mut())
        .expect("Python sink");
    sink.tag = Some("sql-injection".to_string());
    sink.constraints = RuleConstraint(vec![ConstraintKind::ArgTainted {
        arg_tainted: ArgTaintedSpec {
            index: Some(0),
            kw: None,
        },
    }]);
    sink.analysis_semantics = Some(AnalysisSemantics {
        character_constraint: Some(CharacterConstraintSemantics {
            required_excluded_characters: vec!["'".to_string()],
            required_enclosing_literal_delimiter: Some("'".to_string()),
        }),
        ..AnalysisSemantics::default()
    });
    let ws = workspace(&[(
        "/app/search.py",
        r#"
def source():
    return ""

def execute(sql):
    return cursor.execute(sql)

def safe_search():
    body = source()
    q = body.get("q", "")
    safe = "".join(ch for ch in q if ch.isalnum() or ch == " ")[:64]
    sql = f"SELECT * FROM users WHERE name ILIKE '%{safe}%'"
    return execute(sql)

def unsafe_search():
    q = source()
    sql = f"SELECT * FROM users WHERE name ILIKE '%{q}%'"
    return execute(sql)
"#,
    )]);
    let report = run_taint_analysis(
        &ws,
        &pack,
        TaintAnalysisOptions {
            show_sanitized: true,
            ..TaintAnalysisOptions::default()
        },
    )
    .expect("taint analysis");
    let unsafe_finding = report
        .findings
        .first()
        .unwrap_or_else(|| panic!("missing grouped sink finding: {:#?}", report.findings));
    assert_eq!(
        unsafe_finding.finding.status,
        FindingStatus::Unsanitized,
        "{unsafe_finding:#?}"
    );
    let safe = unsafe_finding
        .finding
        .alternate_flows
        .iter()
        .find(|flow| {
            flow.chain_display
                .iter()
                .any(|function| function == "safe_search")
        })
        .unwrap_or_else(|| panic!("missing safe alternate route: {unsafe_finding:#?}"));
    assert_eq!(safe.status, FindingStatus::Sanitized, "{safe:#?}");
    assert!(safe
        .sanitizers_seen
        .iter()
        .any(|sanitizer| { sanitizer.rule_id == "engine.sanitizer.character_constraint" }));

    let unquoted_ws = workspace(&[(
        "/app/order.py",
        r#"
def source():
    return ""

def unsafe_order():
    q = source()
    safe = "".join(ch for ch in q if ch.isalnum() or ch == " ")
    return cursor.execute(f"SELECT * FROM users ORDER BY {safe}")
"#,
    )]);
    let unquoted = run_taint_analysis(
        &unquoted_ws,
        &pack,
        TaintAnalysisOptions {
            show_sanitized: true,
            ..TaintAnalysisOptions::default()
        },
    )
    .expect("taint analysis");
    assert_eq!(unquoted.findings.len(), 1, "{:#?}", unquoted.findings);
    assert_eq!(
        unquoted.findings[0].finding.status,
        FindingStatus::Unsanitized,
        "an alphanumeric allowlist is not a SQL sanitizer in an unquoted grammar position"
    );
}

#[test]
fn regex_character_constraint_summary_sanitizes_only_exact_helper_result() {
    let mut pack = constrained_call_sink_rulepack("python", "source", "sink");
    let sink = pack
        .packs
        .get_mut("python")
        .and_then(|pack| pack.sinks.first_mut())
        .expect("Python sink");
    sink.tag = Some("header-injection".to_string());
    sink.analysis_semantics = Some(AnalysisSemantics {
        character_constraint: Some(CharacterConstraintSemantics {
            required_excluded_characters: vec!["\r".to_string(), "\n".to_string()],
            required_enclosing_literal_delimiter: None,
        }),
        ..AnalysisSemantics::default()
    });
    let ws = workspace(&[(
        "/app/header.py",
        r#"
import re

_UNSAFE = re.compile(r'[\r\n"\\]')

def source():
    return ""

def cleaned(filename: str) -> str:
    return _UNSAFE.sub("_", filename)

def safe_header():
    filename = source()
    value = 'attachment; filename="' + cleaned(filename) + '"'
    sink(value)

def unsafe_header():
    filename = source()
    value = 'attachment; filename="' + filename + '"'
    sink(value)
"#,
    )]);
    let report = run_taint_analysis(&ws, &pack, TaintAnalysisOptions::default()).expect("taint analysis");
    assert_eq!(report.findings.len(), 1, "{:#?}", report.findings);
    assert_eq!(
        report.findings[0].finding.sink.enclosing_fn.as_deref(),
        Some("unsafe_header"),
        "{:#?}",
        report.findings
    );
}

#[test]
fn direct_character_constraint_helper_result_sanitizes_sink_argument() {
    let mut pack = constrained_call_sink_rulepack("go", "source", "sink");
    let sink = pack
        .packs
        .get_mut("go")
        .and_then(|pack| pack.sinks.first_mut())
        .expect("Go sink");
    sink.tag = Some("log-injection".to_string());
    sink.analysis_semantics = Some(AnalysisSemantics {
        character_constraint: Some(CharacterConstraintSemantics {
            required_excluded_characters: vec!["\r".to_string(), "\n".to_string()],
            required_enclosing_literal_delimiter: None,
        }),
        ..AnalysisSemantics::default()
    });
    let ws = workspace(&[(
        "/app/audit.go",
        r#"
package app
import "strings"
func source() string { return "" }
func sanitize(value string) string {
    return strings.Map(func(r rune) rune {
        if r < 0x20 || r == 0x7f { return '_' }
        return r
    }, value)
}
func safe() { sink(sanitize(source())) }
func unsafe() { sink(source()) }
"#,
    )]);
    let report = run_taint_analysis(&ws, &pack, TaintAnalysisOptions::default()).expect("taint analysis");
    assert_eq!(report.findings.len(), 1, "{:#?}", report.findings);
    assert_eq!(
        report.findings[0].finding.sink.enclosing_fn.as_deref(),
        Some("unsafe"),
        "the direct helper result must be discharged while the bypass remains"
    );
}

#[test]
fn library_sanitizer_summary_crosses_first_party_helper_return() {
    let mut pack = constrained_call_sink_rulepack("go", "source", "sink");
    let go = pack.packs.get_mut("go").expect("Go pack");
    go.sinks[0].tag = Some("xss".to_string());
    let mut sanitizer = rule(
        "go",
        RuleKind::Sanitizer,
        "go.test.html_escape",
        None,
        None,
        "html.EscapeString",
    );
    sanitizer.tag = Some("xss".to_string());
    go.sanitizers.push(sanitizer);
    let ws = workspace(&[(
        "/app/render.go",
        r#"
package app
import "html"
func source() string { return "" }
func render(value string) string {
    return "<p>" + html.EscapeString(value) + "</p>"
}
func safe() { output := render(source()); sink(output) }
func unsafe() { sink(source()) }
"#,
    )]);
    let report = run_taint_analysis(&ws, &pack, TaintAnalysisOptions::default()).expect("taint analysis");
    assert_eq!(report.findings.len(), 1, "{:#?}", report.findings);
    assert_eq!(
        report.findings[0].finding.sink.enclosing_fn.as_deref(),
        Some("unsafe"),
        "the exact helper return summary must discharge only the sanitized path"
    );
}

#[test]
fn same_origin_path_summary_sanitizes_only_direct_helper_result() {
    let mut pack = constrained_call_sink_rulepack("python", "source", "sink");
    let sink = pack
        .packs
        .get_mut("python")
        .and_then(|pack| pack.sinks.first_mut())
        .expect("Python sink");
    sink.tag = Some("open-redirect".to_string());
    sink.analysis_semantics = Some(AnalysisSemantics {
        same_origin_path_constraint: Some(bonsai_security::SameOriginPathConstraintSemantics {
            require_scheme_rejection: true,
            require_authority_rejection: true,
            require_absolute_path: true,
            require_scheme_relative_rejection: true,
            sink_argument_index: None,
            static_context_argument: None,
        }),
        ..AnalysisSemantics::default()
    });
    let ws = workspace(&[(
        "/app/redirect.py",
        r#"
from urllib.parse import urlparse

def source():
    return ""

def same_site(target: str) -> str:
    parsed = urlparse(target)
    if parsed.scheme or parsed.netloc or not target.startswith("/") or target.startswith("//"):
        return "/"
    return target

def safe_redirect():
    target = source()
    sink(same_site(target))

def unsafe_redirect():
    target = source()
    sink(target)
"#,
    )]);
    let report = run_taint_analysis(&ws, &pack, TaintAnalysisOptions::default()).expect("taint analysis");
    assert_eq!(report.findings.len(), 1, "{:#?}", report.findings);
    assert_eq!(
        report.findings[0].finding.sink.enclosing_fn.as_deref(),
        Some("unsafe_redirect"),
        "{:#?}",
        report.findings
    );
}

#[test]
fn recursive_dynamic_key_filter_guards_only_exact_helper_output() {
    let mut pack = constrained_call_sink_rulepack("typescript", "source", "merge");
    let sink = pack
        .packs
        .get_mut("typescript")
        .and_then(|pack| pack.sinks.first_mut())
        .expect("TypeScript sink");
    sink.tag = Some("prototype-pollution".to_string());
    sink.constraints = RuleConstraint(vec![ConstraintKind::ArgTainted {
        arg_tainted: ArgTaintedSpec {
            index: Some(1),
            kw: None,
        },
    }]);
    sink.analysis_semantics = Some(AnalysisSemantics {
        dynamic_key_denylist_guard: Some(DynamicKeyDenylistGuardSemantics {
            collection_constructor: RuleTarget {
                name: Some("Set".to_string()),
                ..RuleTarget::default()
            },
            membership_check: RuleTarget {
                name: Some("has".to_string()),
                ..RuleTarget::default()
            },
            membership_subject_arg_index: 0,
            collection_values_arg_index: 0,
            rejected_exact_values: vec![
                "__proto__".to_string(),
                "constructor".to_string(),
                "prototype".to_string(),
            ],
            sink_key_argument_index: None,
            require_recursive_filter: true,
            filtered_value_argument_index: Some(1),
        }),
        ..AnalysisSemantics::default()
    });
    let ws = workspace(&[(
        "/app/merge.ts",
        r#"
const BLOCKED = new Set(["__proto__", "constructor", "prototype"]);
function source(): unknown { return {}; }
function sanitize(value: unknown): unknown {
  if (value && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [key, item] of Object.entries(value as Record<string, unknown>)) {
      if (BLOCKED.has(key)) continue;
      out[key] = sanitize(item);
    }
    return out;
  }
  return value;
}
function shallow(value: any): any { return value; }
function safeApply(): void { merge({}, sanitize(source())); }
function unsafeApply(): void { merge({}, shallow(source())); }
"#,
    )]);
    let report = run_taint_analysis(&ws, &pack, TaintAnalysisOptions::default()).expect("taint analysis");
    assert_eq!(report.findings.len(), 1, "{:#?}", report.findings);
    assert_eq!(
        report.findings[0].finding.sink.enclosing_fn.as_deref(),
        Some("unsafeApply"),
        "only the exact recursive reconstruction may suppress the sink"
    );
}

fn relative_path_containment_semantics(guarded_path_arg_index: Option<usize>) -> AnalysisSemantics {
    AnalysisSemantics {
        guard_profile: Some(GuardProfile::RelativePathContainment),
        relative_path_containment_guard: Some(RelativePathContainmentGuardSemantics {
            candidate_canonicalizer: RuleTarget {
                attribute: Some(vec!["filepath".to_string(), "Clean".to_string()]),
                ..RuleTarget::default()
            },
            base_canonicalizer: RuleTarget {
                attribute: Some(vec!["filepath".to_string(), "Abs".to_string()]),
                ..RuleTarget::default()
            },
            relative_path: RuleTarget {
                attribute: Some(vec!["filepath".to_string(), "Rel".to_string()]),
                ..RuleTarget::default()
            },
            relative_path_result_index: 0,
            relative_base_arg_index: 0,
            relative_candidate_arg_index: 1,
            guarded_path_arg_index,
            rejection_check: RuleTarget {
                attribute: Some(vec!["strings".to_string(), "HasPrefix".to_string()]),
                ..RuleTarget::default()
            },
            rejection_check_arg_index: 0,
            rejection_prefix_arg_index: Some(1),
            rejection_boundary_places: vec!["os.PathSeparator".to_string()],
            rejection_boundary_wrappers: vec![RuleTarget {
                name: Some("string".to_string()),
                ..RuleTarget::default()
            }],
            rejected_exact_values: vec!["..".to_string()],
        }),
        ..AnalysisSemantics::default()
    }
}

#[test]
fn go_relative_path_containment_requires_complete_compiler_proof() {
    let ws = workspace(&[(
        "/app/app.go",
        r#"
package app

import (
    "os"
    "path/filepath"
    "strings"
)

const baseDir = "/var/data/files"

func source() string { return "user" }

func safeRead(baseDir string) ([]byte, error) {
    rootAbs, err := filepath.Abs(baseDir)
    if err != nil { return nil, err }
    candidate := filepath.Clean(filepath.Join(rootAbs, source()))
    rel, err := filepath.Rel(rootAbs, candidate)
    if err != nil || rel == ".." || strings.HasPrefix(rel, ".." + string(os.PathSeparator)) {
        return nil, os.ErrNotExist
    }
    return os.ReadFile(candidate)
}

func entry() { _, _ = safeRead("/var/data/files") }

func guardedDynamicBase() ([]byte, error) {
    baseDir := source()
    rootAbs, err := filepath.Abs(baseDir)
    if err != nil { return nil, err }
    candidate := filepath.Clean(filepath.Join(rootAbs, source()))
    rel, err := filepath.Rel(rootAbs, candidate)
    if err != nil || rel == ".." || strings.HasPrefix(rel, ".." + string(os.PathSeparator)) {
        return nil, os.ErrNotExist
    }
    return os.ReadFile(candidate)
}

func unsafeRead() ([]byte, error) {
    rootAbs, _ := filepath.Abs(baseDir)
    candidate := filepath.Clean(filepath.Join(rootAbs, source()))
    return os.ReadFile(candidate)
}

"#,
    )]);

    let mut consumer_pack = rulepack("go", "source", "os.ReadFile");
    let consumer_sink = &mut consumer_pack.packs.get_mut("go").unwrap().sinks[0];
    consumer_sink.tag = Some("path-traversal".to_string());
    consumer_sink.analysis_semantics = Some(relative_path_containment_semantics(Some(0)));
    consumer_sink.constraints = RuleConstraint(vec![ConstraintKind::ArgTainted {
        arg_tainted: ArgTaintedSpec {
            index: Some(0),
            kw: None,
        },
    }]);

    let report =
        run_taint_analysis(&ws, &consumer_pack, TaintAnalysisOptions::default()).expect("taint analysis");
    assert_eq!(report.findings.len(), 2, "{:#?}", report.findings);
    assert!(
        report
            .findings
            .iter()
            .any(|finding| { finding.finding.sink.enclosing_fn.as_deref() == Some("unsafeRead") }),
        "{:#?}",
        report.findings
    );
    assert!(
        report
            .findings
            .iter()
            .any(|finding| { finding.finding.sink.enclosing_fn.as_deref() == Some("guardedDynamicBase") }),
        "a containment check must not sanitize a caller-supplied dynamic base: {:#?}",
        report.findings
    );

    let explicit = run_taint_analysis(
        &ws,
        &consumer_pack,
        TaintAnalysisOptions {
            show_sanitized: true,
            ..TaintAnalysisOptions::default()
        },
    )
    .expect("taint analysis");
    let safe = explicit
        .findings
        .iter()
        .find(|finding| finding.finding.sink.enclosing_fn.as_deref() == Some("safeRead"))
        .expect("safe read finding");
    assert_eq!(safe.finding.status, FindingStatus::Sanitized, "{safe:#?}");
    assert!(
        safe.finding
            .sanitizers_seen
            .iter()
            .any(|sanitizer| sanitizer.rule_id == "engine.sanitizer.relative_path_containment_guard"),
        "{safe:#?}"
    );

    let mut incomplete_pack = consumer_pack.clone();
    incomplete_pack.packs.get_mut("go").unwrap().sinks[0]
        .analysis_semantics
        .as_mut()
        .unwrap()
        .relative_path_containment_guard
        .as_mut()
        .unwrap()
        .rejected_exact_values = vec!["../".to_string()];
    let incomplete =
        run_taint_analysis(&ws, &incomplete_pack, TaintAnalysisOptions::default()).expect("taint analysis");
    assert!(
        incomplete
            .findings
            .iter()
            .any(|finding| finding.finding.sink.enclosing_fn.as_deref() == Some("safeRead")),
        "the exact rejected relative value is rulepack-owned: {:#?}",
        incomplete.findings
    );

    let mut construction_pack = rulepack("go", "source", "filepath.Join");
    let construction_sink = &mut construction_pack.packs.get_mut("go").unwrap().sinks[0];
    construction_sink.tag = Some("path-traversal".to_string());
    construction_sink.analysis_semantics = Some(relative_path_containment_semantics(None));
    construction_sink.constraints = RuleConstraint(vec![ConstraintKind::ArgTainted {
        arg_tainted: ArgTaintedSpec {
            index: Some(1),
            kw: None,
        },
    }]);
    let construction =
        run_taint_analysis(&ws, &construction_pack, TaintAnalysisOptions::default()).expect("taint analysis");
    assert_eq!(construction.findings.len(), 2, "{:#?}", construction.findings);
    assert!(construction
        .findings
        .iter()
        .any(|finding| { finding.finding.sink.enclosing_fn.as_deref() == Some("unsafeRead") }));
    assert!(construction
        .findings
        .iter()
        .any(|finding| { finding.finding.sink.enclosing_fn.as_deref() == Some("guardedDynamicBase") }));
}

#[test]
fn java_url_constructor_guarded_by_scheme_host_and_private_ip_is_sanitized() {
    let mut pack = rulepack("java", "source", "URL");
    let java_pack = pack.packs.get_mut("java").expect("java pack");
    java_pack.sinks[0].id = "java.ssrf.url_ctor".to_string();
    java_pack.sinks[0].tag = Some("ssrf".to_string());
    let target = |name: &str| RuleTarget {
        name: Some(name.to_string()),
        ..RuleTarget::default()
    };
    java_pack.sinks[0].analysis_semantics = Some(AnalysisSemantics {
        url_network_guard: Some(UrlNetworkGuardSemantics {
            root: UrlGuardRootSemantics::SinkAssignmentTarget,
            parser: target("URL"),
            scheme: UrlSchemeGuardSemantics {
                component: UrlComponentSemantics {
                    field: None,
                    accessor: Some(target("getProtocol")),
                },
                comparison_predicate: Some(target("equalsIgnoreCase")),
                allowed_values: vec!["https".to_string()],
            },
            host_allowlist: UrlHostAllowlistSemantics {
                component: UrlComponentSemantics {
                    field: None,
                    accessor: Some(target("getHost")),
                },
                membership_predicate: Some(target("contains")),
                static_collection_factories: vec![target("of")],
            },
            dns: UrlDnsGuardSemantics {
                resolver: target("getByName"),
                private_address_predicates: [
                    "isLoopbackAddress",
                    "isSiteLocalAddress",
                    "isLinkLocalAddress",
                    "isAnyLocalAddress",
                    "isMulticastAddress",
                ]
                .into_iter()
                .map(target)
                .collect(),
            },
            redirect: None,
        }),
        ..AnalysisSemantics::default()
    });
    java_pack.sinks[0].match_spec.kind = MatchKind::New;
    java_pack.sinks[0].constraints = RuleConstraint(vec![ConstraintKind::ArgTainted {
        arg_tainted: ArgTaintedSpec {
            index: Some(0),
            kw: None,
        },
    }]);

    let ws = workspace(&[(
        "/app/App.java",
        r#"
import java.net.*;
import java.util.*;

class App {
  private static final Set<String> ALLOWED_HOSTS = Set.of("api.example.com");
  static String source() { return ""; }

  void guarded() throws Exception {
    URL parsed = new URL(source());
    if (!"https".equalsIgnoreCase(parsed.getProtocol())) throw new SecurityException("scheme");
    if (!ALLOWED_HOSTS.contains(parsed.getHost())) throw new SecurityException("host");
    InetAddress addr = InetAddress.getByName(parsed.getHost());
    if (addr.isLoopbackAddress() || addr.isSiteLocalAddress() || addr.isLinkLocalAddress()
        || addr.isAnyLocalAddress() || addr.isMulticastAddress()) {
      throw new SecurityException("private-ip");
    }
    parsed.openConnection();
  }
}
"#,
    )]);
    let default_report =
        run_taint_analysis(&ws, &pack, TaintAnalysisOptions::default()).expect("taint analysis");
    assert!(
        default_report.findings.is_empty(),
        "guarded URL constructor should be hidden by default as sanitized: {:#?}",
        default_report.findings
    );
    let explicit_report = run_taint_analysis(
        &ws,
        &pack,
        TaintAnalysisOptions {
            show_sanitized: true,
            ..TaintAnalysisOptions::default()
        },
    )
    .expect("taint analysis");
    assert_eq!(
        explicit_report.findings.len(),
        1,
        "{:#?}",
        explicit_report.findings
    );
    let finding = &explicit_report.findings[0].finding;
    assert_eq!(finding.status, FindingStatus::Sanitized, "{finding:#?}");
    assert!(
        finding
            .sanitizers_seen
            .iter()
            .any(|sanitizer| sanitizer.rule_id == "engine.sanitizer.url_network_guard"),
        "expected Java URL guard evidence, got {:#?}",
        finding.sanitizers_seen
    );

    let missing_host_ws = workspace(&[(
        "/app/App.java",
        r#"
import java.net.*;

class App {
  static String source() { return ""; }

  void unguardedHost() throws Exception {
    URL parsed = new URL(source());
    if (!"https".equalsIgnoreCase(parsed.getProtocol())) throw new SecurityException("scheme");
    InetAddress addr = InetAddress.getByName(parsed.getHost());
    if (addr.isLoopbackAddress() || addr.isSiteLocalAddress() || addr.isLinkLocalAddress()) {
      throw new SecurityException("private-ip");
    }
    parsed.openConnection();
  }
}
"#,
    )]);
    let missing_host_report =
        run_taint_analysis(&missing_host_ws, &pack, TaintAnalysisOptions::default()).expect("taint analysis");
    assert_eq!(
        missing_host_report.findings.len(),
        1,
        "missing host allowlist must remain unsanitized: {:#?}",
        missing_host_report.findings
    );
    assert_eq!(
        missing_host_report.findings[0].finding.status,
        FindingStatus::Unsanitized,
        "{:#?}",
        missing_host_report.findings
    );
}

#[test]
fn go_url_client_guard_requires_exact_ast_projections_dns_and_redirect_callback() {
    let mut pack = rulepack("go", "source", "client.Get");
    let go_pack = pack.packs.get_mut("go").expect("Go pack");
    go_pack.sinks[0].id = "go.ssrf.http_client_get".to_string();
    go_pack.sinks[0].tag = Some("ssrf".to_string());
    let target = |name: &str| RuleTarget {
        name: Some(name.to_string()),
        ..RuleTarget::default()
    };
    go_pack.sinks[0].analysis_semantics = Some(AnalysisSemantics {
        url_network_guard: Some(UrlNetworkGuardSemantics {
            root: UrlGuardRootSemantics::SinkArgumentAccessor {
                argument_index: 0,
                accessor: Box::new(target("String")),
            },
            parser: RuleTarget {
                regex: Some(r"^[A-Za-z_][A-Za-z0-9_]*\.Parse$".to_string()),
                ..RuleTarget::default()
            },
            scheme: UrlSchemeGuardSemantics {
                component: UrlComponentSemantics {
                    field: Some("Scheme".to_string()),
                    accessor: None,
                },
                comparison_predicate: None,
                allowed_values: vec!["https".to_string()],
            },
            host_allowlist: UrlHostAllowlistSemantics {
                component: UrlComponentSemantics {
                    field: None,
                    accessor: Some(target("Hostname")),
                },
                membership_predicate: None,
                static_collection_factories: Vec::new(),
            },
            dns: UrlDnsGuardSemantics {
                resolver: RuleTarget {
                    regex: Some(r"^net\.LookupIP$".to_string()),
                    ..RuleTarget::default()
                },
                private_address_predicates: ["IsLoopback", "IsPrivate", "IsLinkLocalUnicast"]
                    .into_iter()
                    .map(target)
                    .collect(),
            },
            redirect: Some(UrlRedirectGuardSemantics::ReceiverFieldExactCallback {
                field: "CheckRedirect".to_string(),
                required_return_place: "http.ErrUseLastResponse".to_string(),
            }),
        }),
        ..AnalysisSemantics::default()
    });
    go_pack.sinks[0].constraints = RuleConstraint(vec![ConstraintKind::ArgTainted {
        arg_tainted: ArgTaintedSpec {
            index: Some(0),
            kw: None,
        },
    }]);

    let ws = workspace(&[(
        "/app/app.go",
        r#"
package app

import (
    "net"
    "net/http"
    neturl "net/url"
)

var allowedHosts = map[string]bool{"api.example.com": true}

func source() string { return "" }

func guarded() {
    u, err := neturl.Parse(source())
    if err != nil || u.Scheme != "https" || !allowedHosts[u.Hostname()] {
        return
    }
    addrs, err := net.LookupIP(u.Hostname())
    if err != nil {
        return
    }
    for _, ip := range addrs {
        if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() {
            return
        }
    }
    client := &http.Client{
        CheckRedirect: func(*http.Request, []*http.Request) error {
            return http.ErrUseLastResponse
        },
    }
    _, _ = client.Get(u.String())
}

func missingRedirect() {
    u, err := neturl.Parse(source())
    if err != nil || u.Scheme != "https" || !allowedHosts[u.Hostname()] {
        return
    }
    addrs, err := net.LookupIP(u.Hostname())
    if err != nil {
        return
    }
    for _, ip := range addrs {
        if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() {
            return
        }
    }
    client := &http.Client{}
    _, _ = client.Get(u.String())
}
"#,
    )]);

    let default_report =
        run_taint_analysis(&ws, &pack, TaintAnalysisOptions::default()).expect("taint analysis");
    assert_eq!(default_report.findings.len(), 1, "{:#?}", default_report.findings);
    assert_eq!(
        default_report.findings[0].finding.sink.enclosing_fn.as_deref(),
        Some("missingRedirect"),
        "{:#?}",
        default_report.findings
    );

    let explicit_report = run_taint_analysis(
        &ws,
        &pack,
        TaintAnalysisOptions {
            show_sanitized: true,
            ..TaintAnalysisOptions::default()
        },
    )
    .expect("taint analysis");
    let guarded = explicit_report
        .findings
        .iter()
        .find(|finding| finding.finding.sink.enclosing_fn.as_deref() == Some("guarded"))
        .expect("guarded Go URL finding");
    assert_eq!(guarded.finding.status, FindingStatus::Sanitized, "{guarded:#?}");
    assert!(
        guarded
            .finding
            .sanitizers_seen
            .iter()
            .any(|sanitizer| sanitizer.rule_id == "engine.sanitizer.url_network_guard"),
        "{:#?}",
        guarded.finding.sanitizers_seen
    );
}

#[test]
fn java_htmlutils_assignment_output_sanitizes_responseentity_html_body() {
    let pack = bonsai_security::load_rulepack(&rules_root()).expect("rulepack loads");
    let ws = workspace(&[(
        "/app/SearchController.java",
        r#"
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.util.HtmlUtils;

@RestController
class SearchController {
  @GetMapping(value = "/search", produces = MediaType.TEXT_HTML_VALUE)
  public ResponseEntity<String> search(@RequestParam("q") String q) {
    String safe = HtmlUtils.htmlEscape(q == null ? "" : q);
    String body = "<!doctype html><body><h1>Results for: " + safe + "</h1></body>";
    return ResponseEntity.ok(body);
  }
}
"#,
    )]);

    let default_report =
        run_taint_analysis(&ws, &pack, TaintAnalysisOptions::default()).expect("taint analysis");
    assert!(
        default_report
            .findings
            .iter()
            .all(|finding| finding.finding.sink.rule_id != "java.xss.spring_responseentity_ok_html_concat"),
        "HTML-escaped ResponseEntity body should be hidden by default as sanitized: {:#?}",
        default_report.findings
    );

    let explicit_report = run_taint_analysis(
        &ws,
        &pack,
        TaintAnalysisOptions {
            show_sanitized: true,
            ..TaintAnalysisOptions::default()
        },
    )
    .expect("taint analysis");
    let finding = explicit_report
        .findings
        .iter()
        .find(|finding| finding.finding.sink.rule_id == "java.xss.spring_responseentity_ok_html_concat")
        .unwrap_or_else(|| {
            panic!(
                "expected sanitized XSS finding, got {:#?}",
                explicit_report.findings
            )
        });
    assert_eq!(finding.finding.status, FindingStatus::Sanitized, "{finding:#?}");
    assert!(
        finding
            .finding
            .sanitizers_seen
            .iter()
            .any(|sanitizer| sanitizer.rule_id == "java.sanitizer.spring_htmlutils"),
        "expected HtmlUtils sanitizer evidence, got {:#?}",
        finding.finding.sanitizers_seen
    );

    let unsafe_ws = workspace(&[(
        "/app/SearchController.java",
        r#"
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
class SearchController {
  @GetMapping(value = "/search", produces = MediaType.TEXT_HTML_VALUE)
  public ResponseEntity<String> search(@RequestParam("q") String q) {
    String body = "<!doctype html><body><h1>Results for: " + q + "</h1></body>";
    return ResponseEntity.ok(body);
  }
}
"#,
    )]);
    let unsafe_report =
        run_taint_analysis(&unsafe_ws, &pack, TaintAnalysisOptions::default()).expect("taint analysis");
    assert!(
        unsafe_report
            .findings
            .iter()
            .any(
                |finding| finding.finding.sink.rule_id == "java.xss.spring_responseentity_ok_html_concat"
                    && finding.finding.status == FindingStatus::Unsanitized
            ),
        "raw ResponseEntity body must remain an unsanitized finding: {:#?}",
        unsafe_report.findings
    );
}

#[test]
fn java_same_origin_path_guard_sanitizes_spring_redirect_headers() {
    let pack = bonsai_security::load_rulepack(&rules_root()).expect("rulepack loads");
    let ws = workspace(&[(
        "/app/RedirController.java",
        r#"
import java.net.URI;
import org.springframework.http.*;
import org.springframework.web.bind.annotation.*;

@RestController
class RedirController {
  @GetMapping("/return")
  public ResponseEntity<Void> bounce(@RequestParam("next") String next) {
    if (next == null || !next.startsWith("/") || next.startsWith("//")) next = "/";
    HttpHeaders h = new HttpHeaders();
    h.setLocation(URI.create(next));
    return new ResponseEntity<>(h, HttpStatus.FOUND);
  }
}
"#,
    )]);

    let default_report =
        run_taint_analysis(&ws, &pack, TaintAnalysisOptions::default()).expect("taint analysis");
    assert!(
        default_report.findings.iter().all(|finding| {
            !matches!(
                finding.finding.sink.rule_id.as_str(),
                "java.open_redirect.spring_httpheaders_setlocation"
                    | "java.open_redirect.spring_responseentity_redirect_headers"
            )
        }),
        "same-origin redirect guard should hide sanitized redirect findings by default: {:#?}",
        default_report.findings
    );

    let explicit_report = run_taint_analysis(
        &ws,
        &pack,
        TaintAnalysisOptions {
            show_sanitized: true,
            ..TaintAnalysisOptions::default()
        },
    )
    .expect("taint analysis");
    for rule_id in [
        "java.open_redirect.spring_httpheaders_setlocation",
        "java.open_redirect.spring_responseentity_redirect_headers",
    ] {
        let finding = explicit_report
            .findings
            .iter()
            .find(|finding| finding.finding.sink.rule_id == rule_id)
            .unwrap_or_else(|| {
                panic!(
                    "expected sanitized {rule_id}, got {:#?}",
                    explicit_report.findings
                )
            });
        assert_eq!(finding.finding.status, FindingStatus::Sanitized, "{finding:#?}");
        assert!(
            finding
                .finding
                .sanitizers_seen
                .iter()
                .any(|sanitizer| { sanitizer.rule_id == "java.sanitizer.same_origin_path_startswith_slash" }),
            "expected same-origin path guard evidence for {rule_id}, got {:#?}",
            finding.finding.sanitizers_seen
        );
    }

    let unsafe_ws = workspace(&[(
        "/app/RedirController.java",
        r#"
import java.net.URI;
import org.springframework.http.*;
import org.springframework.web.bind.annotation.*;

@RestController
class RedirController {
  @GetMapping("/return")
  public ResponseEntity<Void> bounce(@RequestParam("next") String next) {
    HttpHeaders h = new HttpHeaders();
    h.setLocation(URI.create(next));
    return new ResponseEntity<>(h, HttpStatus.FOUND);
  }
}
"#,
    )]);
    let unsafe_report =
        run_taint_analysis(&unsafe_ws, &pack, TaintAnalysisOptions::default()).expect("taint analysis");
    assert!(
        unsafe_report.findings.iter().any(|finding| {
            finding.finding.sink.rule_id == "java.open_redirect.spring_httpheaders_setlocation"
                && finding.finding.status == FindingStatus::Unsanitized
        }),
        "unguarded redirect target must remain unsanitized: {:#?}",
        unsafe_report.findings
    );
}

#[test]
fn typescript_host_allowlist_private_ip_guard_sanitizes_fetch_ssrf() {
    let pack = bonsai_security::load_rulepack(&rules_root()).expect("rulepack loads");
    let ws = workspace(&[
        (
            "/src/routes/webhook.ts",
            r#"
import { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { relay } from "../services/relay";

export default async function (app: FastifyInstance) {
  app.post("/webhook", async (req: FastifyRequest, reply: FastifyReply) => {
    const host = String(req.headers["x-callback-host"] ?? "");
    const path = String((req.body as any)?.path ?? "/ingest");
    const body = await relay(host, path, req.body);
    return reply.send({ relayed: true, body });
  });
}
"#,
        ),
        (
            "/src/services/relay.ts",
            r#"
import fetch from "node-fetch";
import { lookup } from "node:dns/promises";
import net from "node:net";

const ALLOWED_HOSTS = new Set(["ingest.partner-a.com", "ingest.partner-b.com"]);

export async function relay(host: string, path: string, body: unknown): Promise<string> {
  if (!ALLOWED_HOSTS.has(host)) throw new Error("blocked: host");
  const { address } = await lookup(host);
  if (!net.isIP(address) || isPrivateOrLoopback(address)) throw new Error("blocked: ip");
  const url = `https://${host}${path}`;
  const resp = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body ?? {}),
    redirect: "manual",
  });
  return await resp.text();
}

function isPrivateOrLoopback(ip: string): boolean {
  if (ip === "127.0.0.1" || ip === "::1") return true;
  if (ip.startsWith("10.") || ip.startsWith("192.168.") ||
      ip.startsWith("169.254.") || ip.startsWith("fc") || ip.startsWith("fd")) return true;
  if (ip.startsWith("172.")) {
    const o = parseInt(ip.split(".")[1], 10);
    return o >= 16 && o <= 31;
  }
  return false;
}
"#,
        ),
    ]);

    let default_report =
        run_taint_analysis(&ws, &pack, TaintAnalysisOptions::default()).expect("taint analysis");
    assert!(
        default_report
            .findings
            .iter()
            .all(|finding| finding.finding.sink.rule_id != "typescript.ssrf.node_fetch"),
        "host allowlist/private-IP guard should hide sanitized fetch SSRF findings by default: {:#?}",
        default_report.findings
    );

    let explicit_report = run_taint_analysis(
        &ws,
        &pack,
        TaintAnalysisOptions {
            show_sanitized: true,
            ..TaintAnalysisOptions::default()
        },
    )
    .expect("taint analysis");
    let fetch_findings: Vec<_> = explicit_report
        .findings
        .iter()
        .filter(|finding| finding.finding.sink.rule_id == "typescript.ssrf.node_fetch")
        .collect();
    assert!(!fetch_findings.is_empty(), "{:#?}", explicit_report.findings);
    for finding in fetch_findings {
        assert_eq!(finding.finding.status, FindingStatus::Sanitized, "{finding:#?}");
        assert!(
            finding
                .finding
                .sanitizers_seen
                .iter()
                .any(|sanitizer| sanitizer.rule_id == "typescript.sanitizer.allowed_hosts_set_has"),
            "expected host allowlist evidence, got {:#?}",
            finding.finding.sanitizers_seen
        );
    }

    let unsafe_ws = workspace(&[
        (
            "/src/routes/webhook.ts",
            r#"
import { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { relay } from "../services/relay";

export default async function (app: FastifyInstance) {
  app.post("/webhook", async (req: FastifyRequest, reply: FastifyReply) => {
    const host = String(req.headers["x-callback-host"] ?? "");
    return relay(host, "/ingest", req.body);
  });
}
"#,
        ),
        (
            "/src/services/relay.ts",
            r#"
import fetch from "node-fetch";

export async function relay(host: string, path: string, body: unknown): Promise<string> {
  const url = `https://${host}${path}`;
  const resp = await fetch(url, { method: "POST", body: JSON.stringify(body ?? {}) });
  return await resp.text();
}
"#,
        ),
    ]);
    let unsafe_report =
        run_taint_analysis(&unsafe_ws, &pack, TaintAnalysisOptions::default()).expect("taint analysis");
    assert!(
        unsafe_report.findings.iter().any(|finding| {
            finding.finding.sink.rule_id == "typescript.ssrf.node_fetch"
                && finding.finding.status == FindingStatus::Unsanitized
        }),
        "unguarded fetch target must remain unsanitized: {:#?}",
        unsafe_report.findings
    );
}

#[test]
fn javascript_mongo_eq_filter_wrapper_is_sanitized() {
    let mut pack = constrained_call_sink_rulepack("javascript", "source", "Users.findOne");
    let js_pack = pack.packs.get_mut("javascript").expect("javascript pack");
    js_pack.sinks[0].id = "javascript.nosql.mongo_find".to_string();
    js_pack.sinks[0].tag = Some("nosql-injection".to_string());
    js_pack.sinks[0].analysis_semantics = Some(AnalysisSemantics {
        nosql_filter: Some(NoSqlFilterSemantics {
            filter_arg_index: 0,
            literal_value_operators: vec!["$eq".to_string()],
            safe_scalar_runtime_types: Vec::new(),
            safe_scalar_compiler_types: Vec::new(),
            safe_scalar_source_rules: Vec::new(),
        }),
        ..AnalysisSemantics::default()
    });

    let ws = workspace(&[(
        "/app/auth.js",
        r#"
function source() { return ""; }
function login() {
  const email = source();
  return Users.findOne({ email: { $eq: email } });
}
"#,
    )]);
    let default_report =
        run_taint_analysis(&ws, &pack, TaintAnalysisOptions::default()).expect("taint analysis");
    assert!(
        default_report.findings.is_empty(),
        "$eq-only Mongo filter should be hidden by default as sanitized: {:#?}",
        default_report.findings
    );
    let explicit_report = run_taint_analysis(
        &ws,
        &pack,
        TaintAnalysisOptions {
            show_sanitized: true,
            ..TaintAnalysisOptions::default()
        },
    )
    .expect("taint analysis");
    assert_eq!(
        explicit_report.findings.len(),
        1,
        "{:#?}",
        explicit_report.findings
    );
    let finding = &explicit_report.findings[0].finding;
    assert_eq!(finding.status, FindingStatus::Sanitized, "{finding:#?}");
    assert!(
        finding
            .sanitizers_seen
            .iter()
            .any(|sanitizer| sanitizer.rule_id == "engine.sanitizer.nosql_literal_operator_filter"),
        "expected NoSQL $eq wrapper sanitizer evidence, got {:#?}",
        finding.sanitizers_seen
    );

    let unsafe_ws = workspace(&[(
        "/app/auth.js",
        r#"
function source() { return ""; }
function login() {
  const email = source();
  return Users.findOne({ email });
}
"#,
    )]);
    let unsafe_report =
        run_taint_analysis(&unsafe_ws, &pack, TaintAnalysisOptions::default()).expect("taint analysis");
    assert_eq!(
        unsafe_report.findings.len(),
        1,
        "shorthand Mongo filter must remain unsanitized: {:#?}",
        unsafe_report.findings
    );
}

#[test]
fn python_f_string_allowlist_reassignment_cleans_sink_arg() {
    let pack = constrained_call_sink_rulepack("python", "source", "engine.execute");

    let ws = workspace(&[(
        "/app/export.py",
        r#"
class Engine:
    def execute(self, sql):
        pass

engine = Engine()

def source():
    return ""

def render_template():
    name = source()
    name = name if name in {"default", "long", "short", "audit"} else "default"
    return engine.execute(f"SELECT body FROM export_templates WHERE name = '{name}' LIMIT 1")
"#,
    )]);
    let report = run_taint_analysis(&ws, &pack, TaintAnalysisOptions::default()).expect("taint analysis");
    assert!(
        report.findings.is_empty(),
        "allowlist reassignment should clean identifiers interpolated through Python f-strings: {:#?}",
        report.findings
    );

    let unsafe_ws = workspace(&[(
        "/app/export.py",
        r#"
class Engine:
    def execute(self, sql):
        pass

engine = Engine()

def source():
    return ""

def render_template():
    name = source()
    return engine.execute(f"SELECT body FROM export_templates WHERE name = '{name}' LIMIT 1")
"#,
    )]);
    let unsafe_report =
        run_taint_analysis(&unsafe_ws, &pack, TaintAnalysisOptions::default()).expect("taint analysis");
    assert_eq!(
        unsafe_report.findings.len(),
        1,
        "unsafe f-string interpolation must remain reported: {:#?}",
        unsafe_report.findings
    );
}

#[test]
fn local_environment_source_to_log_injection_is_low_signal() {
    let mut pack = constrained_call_sink_rulepack("go", "os.Getenv", "log.Printf");
    let go_pack = pack.packs.get_mut("go").expect("go pack");
    go_pack.sources[0].id = "go.os.getenv".to_string();
    go_pack.sources[0].trust = Some(TrustClass::Local);
    go_pack.sources[0].category = Some("local-input".to_string());
    go_pack.sources[0].analysis_semantics = Some(AnalysisSemantics {
        flow_classes: vec![FlowClass::EnvironmentInput],
        ..AnalysisSemantics::default()
    });
    go_pack.sinks[0].id = "go.log_injection.log_printf_tainted_value".to_string();
    go_pack.sinks[0].tag = Some("log-injection".to_string());

    let ws = workspace(&[(
        "/app/main.go",
        r#"
package main

import (
  "log"
  "os"
)

func main() {
  port := os.Getenv("PORT")
  log.Printf("listening on :%s", port)
}
"#,
    )]);
    let report = run_taint_analysis(&ws, &pack, TaintAnalysisOptions::default()).expect("taint analysis");
    assert!(
        report.findings.is_empty(),
        "local environment/config values logged at startup should not be reported as log injection: {:#?}",
        report.findings
    );

    let remote_pack = constrained_call_sink_rulepack("go", "remote", "log.Printf");
    let remote_ws = workspace(&[(
        "/app/main.go",
        r#"
package main

import "log"

func remote() string { return "" }

func handler() {
  ua := remote()
  log.Printf(ua)
}
"#,
    )]);
    let remote_report = run_taint_analysis(&remote_ws, &remote_pack, TaintAnalysisOptions::default())
        .expect("taint analysis");
    assert_eq!(
        remote_report.findings.len(),
        1,
        "remote request-like values must still report when logged: {:#?}",
        remote_report.findings
    );
}

#[test]
fn python_local_ldap_escape_helper_is_sanitized() {
    let mut pack = constrained_call_sink_rulepack("python", "source", "conn.search");
    let py_pack = pack.packs.get_mut("python").expect("python pack");
    py_pack.sinks[0].id = "python.ldap.ldap3_connection_search_method".to_string();
    py_pack.sinks[0].tag = Some("ldap-injection".to_string());
    py_pack.sinks[0].constraints = RuleConstraint(vec![ConstraintKind::ArgTainted {
        arg_tainted: ArgTaintedSpec {
            index: Some(1),
            kw: None,
        },
    }]);

    let ws = workspace(&[(
        "/app/directory.py",
        r#"
_LDAP_ESCAPES = {"\\": r"\5c", "*": r"\2a", "(": r"\28", ")": r"\29", "\x00": r"\00"}

def _escape(value):
    return "".join(_LDAP_ESCAPES.get(ch, ch) for ch in (value or ""))

def source():
    return ""

def find(conn):
    cn = source()
    filt = "(&(objectClass=person)(cn=" + _escape(cn) + "))"
    return conn.search("ou=people", filt)
"#,
    )]);
    let default_report =
        run_taint_analysis(&ws, &pack, TaintAnalysisOptions::default()).expect("taint analysis");
    assert!(
        default_report.findings.is_empty(),
        "local RFC4515 helper should hide LDAP finding by default: {:#?}",
        default_report.findings
    );
    let explicit_report = run_taint_analysis(
        &ws,
        &pack,
        TaintAnalysisOptions {
            show_sanitized: true,
            ..TaintAnalysisOptions::default()
        },
    )
    .expect("taint analysis");
    assert_eq!(
        explicit_report.findings.len(),
        1,
        "{:#?}",
        explicit_report.findings
    );
    let finding = &explicit_report.findings[0].finding;
    assert_eq!(finding.status, FindingStatus::Sanitized, "{finding:#?}");
    assert!(
        finding
            .sanitizers_seen
            .iter()
            .any(|sanitizer| sanitizer.rule_id == "engine.sanitizer.local_ldap_escape_helper"),
        "expected local LDAP escape sanitizer evidence, got {:#?}",
        finding.sanitizers_seen
    );
}

#[test]
fn go_same_origin_redirect_helper_guard_is_sanitized() {
    let mut pack = constrained_call_sink_rulepack("go", "source", "c.Redirect");
    let go_pack = pack.packs.get_mut("go").expect("go pack");
    go_pack.sinks[0].id = "go.open_redirect.framework_redirect_status_url".to_string();
    go_pack.sinks[0].tag = Some("open-redirect".to_string());
    go_pack.sinks[0].constraints = RuleConstraint(vec![ConstraintKind::ArgTainted {
        arg_tainted: ArgTaintedSpec {
            index: Some(1),
            kw: None,
        },
    }]);

    let ws = workspace(&[(
        "/app/redirect.go",
        r#"
package main

func source() string { return "" }

func BounceTo(c interface{ Redirect(int, string) }) {
	target := source()
	if !startsWithSingleSlash(target) {
		target = "/"
	}
	c.Redirect(302, target)
}

func startsWithSingleSlash(s string) bool {
	return len(s) > 0 && s[0] == '/' && (len(s) == 1 || s[1] != '/')
}
"#,
    )]);
    let default_report =
        run_taint_analysis(&ws, &pack, TaintAnalysisOptions::default()).expect("taint analysis");
    assert!(
        default_report.findings.is_empty(),
        "same-origin redirect helper should hide finding by default: {:#?}",
        default_report.findings
    );
    let explicit_report = run_taint_analysis(
        &ws,
        &pack,
        TaintAnalysisOptions {
            show_sanitized: true,
            ..TaintAnalysisOptions::default()
        },
    )
    .expect("taint analysis");
    assert_eq!(
        explicit_report.findings.len(),
        1,
        "{:#?}",
        explicit_report.findings
    );
    let finding = &explicit_report.findings[0].finding;
    assert_eq!(finding.status, FindingStatus::Sanitized, "{finding:#?}");
    assert!(
        finding
            .sanitizers_seen
            .iter()
            .any(|sanitizer| sanitizer.rule_id == "engine.sanitizer.go_same_origin_redirect_helper_guard"),
        "expected Go same-origin helper sanitizer evidence, got {:#?}",
        finding.sanitizers_seen
    );
}

#[test]
fn python_ssrf_url_guard_is_sanitized() {
    let mut pack = constrained_call_sink_rulepack("python", "source", "c.get");
    let py_pack = pack.packs.get_mut("python").expect("python pack");
    py_pack.sinks[0].id = "python.ssrf.httpx_async_client_get".to_string();
    py_pack.sinks[0].tag = Some("ssrf".to_string());

    let ws = workspace(&[(
        "/app/svc.py",
        r#"
import ipaddress
import socket
from urllib.parse import urlparse
import httpx

ALLOWED = {"api.example.com"}

def source():
    return ""

async def probe():
    url = source()
    u = urlparse(url)
    if u.scheme != "https" or (u.hostname or "") not in ALLOWED:
        raise PermissionError("blocked: host")
    for fam, *_, sa in socket.getaddrinfo(u.hostname, u.port or 443):
        ip = ipaddress.ip_address(sa[0])
        if ip.is_private or ip.is_loopback or ip.is_link_local:
            raise PermissionError("blocked: ip")
    async with httpx.AsyncClient(timeout=5.0, follow_redirects=False) as c:
        resp = await c.get(url)
        return resp.text
"#,
    )]);
    let default_report =
        run_taint_analysis(&ws, &pack, TaintAnalysisOptions::default()).expect("taint analysis");
    assert!(
        default_report.findings.is_empty(),
        "scheme/host/private-IP SSRF guard should hide finding by default: {:#?}",
        default_report.findings
    );
    let explicit_report = run_taint_analysis(
        &ws,
        &pack,
        TaintAnalysisOptions {
            show_sanitized: true,
            ..TaintAnalysisOptions::default()
        },
    )
    .expect("taint analysis");
    assert_eq!(
        explicit_report.findings.len(),
        1,
        "{:#?}",
        explicit_report.findings
    );
    let finding = &explicit_report.findings[0].finding;
    assert_eq!(finding.status, FindingStatus::Sanitized, "{finding:#?}");
    assert!(
        finding
            .sanitizers_seen
            .iter()
            .any(|sanitizer| sanitizer.rule_id == "engine.sanitizer.python_url_ssrf_guard"),
        "expected Python SSRF guard sanitizer evidence, got {:#?}",
        finding.sanitizers_seen
    );
}

#[test]
fn python_url_reconstruction_helper_requires_exact_compiler_facts() {
    let mut pack = constrained_call_sink_rulepack("python", "source", "requests.get");
    let py_pack = pack.packs.get_mut("python").expect("python pack");
    py_pack.sinks[0].id = "python.ssrf.requests_get".to_string();
    py_pack.sinks[0].tag = Some("ssrf".to_string());
    py_pack.sinks[0].analysis_semantics = Some(AnalysisSemantics {
        url_reconstruction_guard: Some(UrlReconstructionGuardSemantics {
            sink_argument_index: 0,
            parser: RuleTarget {
                name: Some("urlparse".to_string()),
                ..RuleTarget::default()
            },
            scheme: UrlSchemeGuardSemantics {
                component: UrlComponentSemantics {
                    field: Some("scheme".to_string()),
                    accessor: None,
                },
                comparison_predicate: None,
                allowed_values: vec!["https".to_string()],
            },
            host_allowlist: UrlHostAllowlistSemantics {
                component: UrlComponentSemantics {
                    field: Some("hostname".to_string()),
                    accessor: None,
                },
                membership_predicate: None,
                static_collection_factories: Vec::new(),
            },
            path_component: UrlComponentSemantics {
                field: Some("path".to_string()),
                accessor: None,
            },
            path_fallback: Some("/".to_string()),
            redirect: None,
            required_sink_named_arguments: vec![RequiredNamedArgumentSemantics {
                name: "allow_redirects".to_string(),
                value: StaticScalarValue::Boolean(false),
            }],
        }),
        ..AnalysisSemantics::default()
    });
    let mut urlopen_sink = py_pack.sinks[0].clone();
    urlopen_sink.id = "python.ssrf.urllib_request".to_string();
    urlopen_sink.match_spec.callee = Some(RuleTarget {
        attribute: Some(vec!["request".to_string(), "urlopen".to_string()]),
        ..RuleTarget::default()
    });
    urlopen_sink
        .analysis_semantics
        .as_mut()
        .and_then(|semantics| semantics.url_reconstruction_guard.as_mut())
        .expect("url reconstruction semantics")
        .required_sink_named_arguments
        .clear();
    py_pack.sinks.push(urlopen_sink);

    let ws = workspace(&[(
        "/app/svc.py",
        r#"
from urllib.parse import urlparse
from urllib import request
import requests

ALLOWED = {"api.partner.example", "cdn.partner.example"}

def source():
    return ""

def checked(url):
    parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.hostname not in ALLOWED:
        raise ValueError("blocked")
    return "https://" + parsed.hostname + (parsed.path or "/")

def returns_original(url):
    parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.hostname not in ALLOWED:
        raise ValueError("blocked")
    return url

def dynamic_hosts():
    return set()

def uses_dynamic_allowlist(url):
    allowed = dynamic_hosts()
    parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.hostname not in allowed:
        raise ValueError("blocked")
    return "https://" + parsed.hostname + (parsed.path or "/")

def swaps_parser_result(url):
    parsed = urlparse(url)
    if parsed.scheme != "https":
        raise ValueError("blocked")
    parsed = dynamic_parts(url)
    if parsed.hostname not in ALLOWED:
        raise ValueError("blocked")
    return "https://" + parsed.hostname + (parsed.path or "/")

def dynamic_parts(url):
    return url

def guarded():
    url = source()
    return requests.get(checked(url), allow_redirects=False)

def guarded_urlopen():
    url = source()
    return request.urlopen(checked(url), timeout=5)

def unsafe_original():
    url = source()
    return requests.get(returns_original(url), allow_redirects=False)

def unsafe_dynamic_allowlist():
    url = source()
    return requests.get(uses_dynamic_allowlist(url), allow_redirects=False)

def unsafe_overwrite():
    url = source()
    return requests.get(swaps_parser_result(url), allow_redirects=False)

def unsafe_redirects():
    url = source()
    return requests.get(checked(url))
"#,
    )]);
    let report = run_taint_analysis(&ws, &pack, TaintAnalysisOptions::default()).expect("taint analysis");
    let functions: BTreeSet<_> = report
        .findings
        .iter()
        .filter_map(|finding| finding.finding.sink.enclosing_fn.as_deref())
        .collect();
    assert_eq!(
        functions,
        BTreeSet::from([
            "unsafe_dynamic_allowlist",
            "unsafe_original",
            "unsafe_overwrite",
            "unsafe_redirects",
        ]),
        "{:#?}",
        report.findings
    );
    assert!(
        report
            .findings
            .iter()
            .all(|finding| finding.finding.status == FindingStatus::Unsanitized),
        "{:#?}",
        report.findings
    );

    let explicit = run_taint_analysis(
        &ws,
        &pack,
        TaintAnalysisOptions {
            show_sanitized: true,
            ..TaintAnalysisOptions::default()
        },
    )
    .expect("taint analysis");
    let guarded = explicit
        .findings
        .iter()
        .find(|finding| finding.finding.sink.enclosing_fn.as_deref() == Some("guarded"))
        .expect("guarded reconstruction finding");
    assert_eq!(guarded.finding.status, FindingStatus::Sanitized, "{guarded:#?}");
    assert!(
        guarded
            .finding
            .sanitizers_seen
            .iter()
            .any(|sanitizer| sanitizer.rule_id == "engine.sanitizer.url_reconstruction_guard"),
        "{:#?}",
        guarded.finding.sanitizers_seen
    );
    let guarded_urlopen = explicit
        .findings
        .iter()
        .find(|finding| finding.finding.sink.enclosing_fn.as_deref() == Some("guarded_urlopen"))
        .expect("guarded urlopen reconstruction finding");
    assert_eq!(
        guarded_urlopen.finding.status,
        FindingStatus::Sanitized,
        "{guarded_urlopen:#?}"
    );
}

#[test]
fn java_url_reconstruction_assignment_requires_exact_components_and_guards() {
    let mut pack = constrained_call_sink_rulepack("java", "source", "ws.url");
    let sink = pack
        .packs
        .get_mut("java")
        .and_then(|pack| pack.sinks.first_mut())
        .expect("Java sink");
    sink.tag = Some("ssrf".to_string());
    let target = |name: &str| RuleTarget {
        name: Some(name.to_string()),
        ..RuleTarget::default()
    };
    sink.analysis_semantics = Some(AnalysisSemantics {
        url_reconstruction_guard: Some(UrlReconstructionGuardSemantics {
            sink_argument_index: 0,
            parser: RuleTarget {
                attribute: Some(vec!["URI".to_string(), "create".to_string()]),
                ..RuleTarget::default()
            },
            scheme: UrlSchemeGuardSemantics {
                component: UrlComponentSemantics {
                    field: None,
                    accessor: Some(target("getScheme")),
                },
                comparison_predicate: Some(target("equals")),
                allowed_values: vec!["https".to_string()],
            },
            host_allowlist: UrlHostAllowlistSemantics {
                component: UrlComponentSemantics {
                    field: None,
                    accessor: Some(target("getHost")),
                },
                membership_predicate: Some(target("contains")),
                static_collection_factories: vec![RuleTarget {
                    attribute: Some(vec!["Set".to_string(), "of".to_string()]),
                    ..RuleTarget::default()
                }],
            },
            path_component: UrlComponentSemantics {
                field: None,
                accessor: Some(target("getPath")),
            },
            path_fallback: Some("/".to_string()),
            redirect: None,
            required_sink_named_arguments: Vec::new(),
        }),
        ..AnalysisSemantics::default()
    });
    let ws = workspace(&[(
        "/app/UrlProbe.java",
        r#"
import java.net.URI;
import java.util.Set;

class Client { void url(String value) {} }
class UrlProbe {
  static final Set<String> ALLOWED = Set.of("api.example.test");
  Client ws = new Client();
  static String source() { return ""; }

  void entry() {
    guarded(source());
    missingHostGuard(source());
  }

  void guarded(String url) {
    URI uri = URI.create(url);
    if (!"https".equals(uri.getScheme()) || !ALLOWED.contains(uri.getHost())) {
      throw new IllegalArgumentException();
    }
    String safe = "https://" + uri.getHost() + (uri.getPath() == null ? "/" : uri.getPath());
    ws.url(safe);
  }

  void missingHostGuard(String url) {
    URI uri = URI.create(url);
    if (!"https".equals(uri.getScheme())) throw new IllegalArgumentException();
    String safe = "https://" + uri.getHost() + (uri.getPath() == null ? "/" : uri.getPath());
    ws.url(safe);
  }
}
"#,
    )]);
    let report = run_taint_analysis(&ws, &pack, TaintAnalysisOptions::default()).expect("taint analysis");
    assert_eq!(report.findings.len(), 1, "{:#?}", report.findings);
    assert_eq!(
        report.findings[0].finding.sink.enclosing_fn.as_deref(),
        Some("missingHostGuard"),
        "{:#?}",
        report.findings
    );
}

#[test]
fn go_jwt_parse_inline_keyfunc_with_algorithm_pin_is_sanitized() {
    let mut pack = constrained_call_sink_rulepack("go", "source", "jwt.Parse");
    let go_pack = pack.packs.get_mut("go").expect("go pack");
    go_pack.sinks[0].id = "go.jwt.golang_jwt_parse_tainted_token".to_string();
    go_pack.sinks[0].tag = Some("jwt".to_string());
    go_pack.sinks[0].analysis_semantics = Some(AnalysisSemantics {
        guard_profile: Some(GuardProfile::GoJwtInlineKeyfuncAlgorithm),
        ..AnalysisSemantics::default()
    });

    let ws = workspace(&[(
        "/app/main.go",
        r#"
package main

import (
  "github.com/golang-jwt/jwt/v5"
)

func source() string { return "" }

func verify(key []byte) (*jwt.Token, error) {
  return jwt.Parse(source(), func(t *jwt.Token) (any, error) {
    if t.Method.Alg() != "HS256" {
      return nil, jwt.ErrSignatureInvalid
    }
    return key, nil
  })
}
"#,
    )]);
    let default_report =
        run_taint_analysis(&ws, &pack, TaintAnalysisOptions::default()).expect("taint analysis");
    assert!(
        default_report.findings.is_empty(),
        "algorithm-pinned keyfunc should hide the JWT finding by default: {:#?}",
        default_report.findings
    );
    let explicit_report = run_taint_analysis(
        &ws,
        &pack,
        TaintAnalysisOptions {
            show_sanitized: true,
            ..TaintAnalysisOptions::default()
        },
    )
    .expect("taint analysis");
    assert_eq!(
        explicit_report.findings.len(),
        1,
        "{:#?}",
        explicit_report.findings
    );
    let finding = &explicit_report.findings[0].finding;
    assert_eq!(finding.status, FindingStatus::Sanitized, "{finding:#?}");
    assert!(
        finding
            .sanitizers_seen
            .iter()
            .any(|sanitizer| sanitizer.rule_id == "engine.sanitizer.go_jwt_inline_keyfunc_algorithm_guard"),
        "expected Go JWT keyfunc sanitizer evidence, got {:#?}",
        finding.sanitizers_seen
    );

    let unsafe_ws = workspace(&[(
        "/app/main.go",
        r#"
package main

import (
  "github.com/golang-jwt/jwt/v5"
)

func source() string { return "" }

func verify(key []byte) (*jwt.Token, error) {
  return jwt.Parse(source(), func(t *jwt.Token) (any, error) {
    return key, nil
  })
}
"#,
    )]);
    let unsafe_report =
        run_taint_analysis(&unsafe_ws, &pack, TaintAnalysisOptions::default()).expect("taint analysis");
    assert_eq!(
        unsafe_report.findings.len(),
        1,
        "keyfunc without algorithm guard must remain unsanitized: {:#?}",
        unsafe_report.findings
    );
    assert_eq!(
        unsafe_report.findings[0].finding.status,
        FindingStatus::Unsanitized,
        "{:#?}",
        unsafe_report.findings
    );
}

#[test]
fn typescript_local_html_escape_helper_sanitizes_xss_sink() {
    let mut pack = constrained_call_sink_rulepack("typescript", "source", "sink");
    let ts_pack = pack.packs.get_mut("typescript").expect("typescript pack");
    ts_pack.sinks[0].id = "typescript.xss.html_return".to_string();
    ts_pack.sinks[0].tag = Some("xss".to_string());

    let ws = workspace(&[(
        "/app/render.ts",
        r#"
const HTML_ESCAPE: Record<string, string> = {
  "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
};
function htmlEscape(s: string): string {
  return s.replace(/[&<>"']/g, (c) => HTML_ESCAPE[c]);
}
function source(): string { return ""; }
function render(): void {
  const id = source();
  sink(`<h1>${htmlEscape(id)}</h1>`);
}
function sink(html: string): void {}
"#,
    )]);
    let default_report =
        run_taint_analysis(&ws, &pack, TaintAnalysisOptions::default()).expect("taint analysis");
    assert!(
        default_report.findings.is_empty(),
        "local HTML escape helper should sanitize the XSS sink by default: {:#?}",
        default_report.findings
    );
    let explicit_report = run_taint_analysis(
        &ws,
        &pack,
        TaintAnalysisOptions {
            show_sanitized: true,
            ..TaintAnalysisOptions::default()
        },
    )
    .expect("taint analysis");
    assert_eq!(
        explicit_report.findings.len(),
        1,
        "{:#?}",
        explicit_report.findings
    );
    let finding = &explicit_report.findings[0].finding;
    assert_eq!(finding.status, FindingStatus::Sanitized, "{finding:#?}");
    assert!(
        finding
            .sanitizers_seen
            .iter()
            .any(|sanitizer| sanitizer.rule_id == "engine.sanitizer.js_ts_local_html_escape_helper"),
        "expected local HTML helper sanitizer evidence, got {:#?}",
        finding.sanitizers_seen
    );

    let unsafe_ws = workspace(&[(
        "/app/render.ts",
        r#"
function htmlEscape(s: string): string {
  return s;
}
function source(): string { return ""; }
function render(): void {
  const id = source();
  sink(`<h1>${htmlEscape(id)}</h1>`);
}
function sink(html: string): void {}
"#,
    )]);
    let unsafe_report =
        run_taint_analysis(&unsafe_ws, &pack, TaintAnalysisOptions::default()).expect("taint analysis");
    assert_eq!(
        unsafe_report.findings.len(),
        1,
        "helper without entity escaping must remain unsanitized: {:#?}",
        unsafe_report.findings
    );
    assert_eq!(
        unsafe_report.findings[0].finding.status,
        FindingStatus::Unsanitized,
        "{:#?}",
        unsafe_report.findings
    );
}

#[test]
fn go_xml_decoder_with_strict_and_allowlisted_charset_reader_is_sanitized() {
    let mut pack = constrained_call_sink_rulepack("go", "source", "xml.NewDecoder");
    let go_pack = pack.packs.get_mut("go").expect("go pack");
    go_pack.sinks[0].id = "go.xxe.xml_newdecoder".to_string();
    go_pack.sinks[0].tag = Some("xxe".to_string());
    go_pack.sinks[0].analysis_semantics = Some(AnalysisSemantics {
        guard_profile: Some(GuardProfile::GoXmlDecoderHardening),
        ..AnalysisSemantics::default()
    });

    let ws = workspace(&[(
        "/app/parse.go",
        r#"
package main

import (
  "encoding/xml"
  "errors"
  "io"
)

var allowedCharsets = map[string]bool{"utf-8": true, "us-ascii": true}
func source() io.Reader { return nil }

func parse() error {
  dec := xml.NewDecoder(source())
  dec.Strict = true
  dec.CharsetReader = func(charset string, input io.Reader) (io.Reader, error) {
    if !allowedCharsets[charset] {
      return nil, errors.New("disallowed charset")
    }
    return input, nil
  }
  var out any
  return dec.Decode(&out)
}
"#,
    )]);
    let default_report =
        run_taint_analysis(&ws, &pack, TaintAnalysisOptions::default()).expect("taint analysis");
    assert!(
        default_report.findings.is_empty(),
        "strict decoder with allowlisted charset reader should be sanitized by default: {:#?}",
        default_report.findings
    );
    let explicit_report = run_taint_analysis(
        &ws,
        &pack,
        TaintAnalysisOptions {
            show_sanitized: true,
            ..TaintAnalysisOptions::default()
        },
    )
    .expect("taint analysis");
    assert_eq!(
        explicit_report.findings.len(),
        1,
        "{:#?}",
        explicit_report.findings
    );
    let finding = &explicit_report.findings[0].finding;
    assert_eq!(finding.status, FindingStatus::Sanitized, "{finding:#?}");
    assert!(
        finding
            .sanitizers_seen
            .iter()
            .any(|sanitizer| sanitizer.rule_id == "engine.sanitizer.go_xml_decoder_hardening"),
        "expected Go XML decoder sanitizer evidence, got {:#?}",
        finding.sanitizers_seen
    );

    let unsafe_ws = workspace(&[(
        "/app/parse.go",
        r#"
package main

import (
  "encoding/xml"
  "io"
)

func source() io.Reader { return nil }

func parse() error {
  dec := xml.NewDecoder(source())
  var out any
  return dec.Decode(&out)
}
"#,
    )]);
    let unsafe_report =
        run_taint_analysis(&unsafe_ws, &pack, TaintAnalysisOptions::default()).expect("taint analysis");
    assert_eq!(
        unsafe_report.findings.len(),
        1,
        "decoder without explicit hardening must remain unsanitized: {:#?}",
        unsafe_report.findings
    );
    assert_eq!(
        unsafe_report.findings[0].finding.status,
        FindingStatus::Unsanitized,
        "{:#?}",
        unsafe_report.findings
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
