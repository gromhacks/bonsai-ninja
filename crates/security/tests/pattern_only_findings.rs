use bonsai_security::loader::LanguagePack;
use bonsai_security::rule::{
    ArgRegexSpec, ArgTaintedSpec, ConstraintKind, MatchKind, MatchSpec, Rule, RuleConstraint, RuleKind,
    RuleTarget, Severity, TaintSemantics,
};
use bonsai_security::{run_taint_analysis, Rulepack, TaintAnalysisOptions};
use bonsai_workspace::Workspace;
use std::sync::Arc;

fn workspace(path: &str, source: &str) -> Workspace {
    workspace_multi(&[(path, source)])
}

fn workspace_multi(files: &[(&str, &str)]) -> Workspace {
    let ws = Workspace::new(bonsai_adapters::all_languages_registry());
    for (path, source) in files {
        ws.vfs().write((*path).to_string(), Arc::<str>::from(*source));
    }
    for file in ws.vfs().all_files() {
        let _ = ws.db().decl_index(file);
        let _ = ws.db().import_index(file);
    }
    ws
}

fn pack_for(lang: &str, sinks: Vec<Rule>) -> Rulepack {
    let mut pack = bonsai_security::load_rulepack(
        &std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join("security-patterns"),
    )
    .expect("bundled rulepack metadata");
    pack.packs.clear();
    let mut sinks = sinks;
    for sink in &mut sinks {
        pack.metadata.apply_rule_defaults(sink);
    }
    pack.packs.insert(
        lang.to_string(),
        LanguagePack {
            language: lang.to_string(),
            sources: Vec::new(),
            sinks,
            sanitizers: Vec::new(),
            typing: Vec::new(),
        },
    );
    pack
}

fn call_name_rule(lang: &str, id: &str, tag: &str, name: &str) -> Rule {
    let mut rule = base_rule(lang, id, tag, MatchKind::Call);
    rule.match_spec.callee = Some(RuleTarget {
        name: Some(name.to_string()),
        ..Default::default()
    });
    rule
}

fn call_attr_rule(lang: &str, id: &str, tag: &str, attr: &[&str]) -> Rule {
    let mut rule = base_rule(lang, id, tag, MatchKind::Call);
    rule.match_spec.callee = Some(RuleTarget {
        attribute: Some(attr.iter().map(|part| (*part).to_string()).collect()),
        ..Default::default()
    });
    rule
}

fn call_regex_rule(lang: &str, id: &str, tag: &str, regex: &str) -> Rule {
    let mut rule = base_rule(lang, id, tag, MatchKind::Call);
    rule.match_spec.callee = Some(RuleTarget {
        regex: Some(regex.to_string()),
        ..Default::default()
    });
    rule
}

fn base_rule(lang: &str, id: &str, tag: &str, kind: MatchKind) -> Rule {
    Rule {
        id: id.to_string(),
        aliases: Vec::new(),
        enabled: true,
        disabled_reason: None,
        title: None,
        tag: Some(tag.to_string()),
        severity: Some(Severity::High),
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
        package_matching: Default::default(),
        payload_types: Vec::new(),
        match_spec: MatchSpec {
            kind,
            callee: None,
            target: None,
            search_depth: 0,
        },
        analysis_semantics: None,
        taint_semantics: None,
        lifecycle_transition: None,
        returns_type: None,
        callback_param_types: Vec::new(),
        callback_arg_index: None,
        constraints: RuleConstraint::default(),
        match_examples: Vec::new(),
        description: "test rule".to_string(),
        kind: RuleKind::Sink,
        language: lang.to_string(),
        source_path: String::new(),
    }
}

#[test]
fn inline_qualified_random_next_reports_as_pattern_only() {
    let ws = workspace(
        "App.java",
        r"
import java.util.*;

class App {
    void handle() {
        new java.util.Random().nextFloat();
    }
}
",
    );
    let sink = call_attr_rule(
        "java",
        "java.test.random_next",
        "weak-randomness",
        &["Random", "nextFloat"],
    );
    let mut sink = sink;
    sink.category = Some("source-independent".to_string());
    let pack = pack_for("java", vec![sink]);

    let report = run_taint_analysis(
        &ws,
        &pack,
        TaintAnalysisOptions {
            include_pattern_only: true,
            ..Default::default()
        },
    )
    .expect("analysis");
    assert!(
        report
            .findings
            .iter()
            .any(|finding| finding.finding.sink.rule_id == "java.test.random_next"),
        "inline qualified java.util.Random receiver should satisfy typed Random.nextFloat matching: {:#?}",
        report.findings
    );
}

#[test]
fn pattern_only_sink_is_hidden_by_default_and_explicit_when_requested() {
    let ws = workspace(
        "App.java",
        r"
class App {
    void handle() {
        Math.random();
    }
}
",
    );
    let mut sink = call_attr_rule(
        "java",
        "java.test.math_random",
        "weak-randomness",
        &["Math", "random"],
    );
    sink.category = Some("source-independent".to_string());
    let pack = pack_for("java", vec![sink]);

    let default_report = run_taint_analysis(&ws, &pack, TaintAnalysisOptions::default()).expect("analysis");
    assert!(
        default_report.findings.is_empty(),
        "default taint-analysis must stay source-to-sink only: {:#?}",
        default_report.findings
    );

    let report = run_taint_analysis(
        &ws,
        &pack,
        TaintAnalysisOptions {
            include_pattern_only: true,
            ..Default::default()
        },
    )
    .expect("analysis");
    let finding = report
        .findings
        .iter()
        .find(|finding| finding.finding.sink.rule_id == "java.test.math_random")
        .unwrap_or_else(|| {
            panic!(
                "pattern-only weak randomness should report without a source flow: {:#?}",
                report.findings
            )
        });
    let group_id = finding.finding.group_id.as_deref().unwrap_or("");
    let flow_id = finding.finding.representative_flow_id.as_deref().unwrap_or("");
    assert!(
        group_id.starts_with("G:") && group_id.len() == 18,
        "pattern-only group_id malformed: {group_id}"
    );
    assert!(
        flow_id.starts_with("F:") && flow_id.len() == 18,
        "pattern-only representative_flow_id malformed: {flow_id}"
    );
}

#[test]
fn source_independent_sink_does_not_fabricate_taint_flow() {
    let ws = workspace(
        "app.py",
        r#"
def handler(user_input):
    dangerous(user_input)
"#,
    );
    let mut sink = call_name_rule(
        "python",
        "python.test.source_independent_config",
        "command-injection",
        "dangerous",
    );
    sink.category = Some("source-independent".to_string());
    let pack = pack_for("python", vec![sink]);

    let default_report = run_taint_analysis(
        &ws,
        &pack,
        TaintAnalysisOptions {
            include_inferred_sources: true,
            ..Default::default()
        },
    )
    .expect("analysis");
    assert!(
        default_report.findings.is_empty(),
        "source-independent rules must not participate in source-to-sink taint matching: {:#?}",
        default_report.findings
    );

    let report = run_taint_analysis(
        &ws,
        &pack,
        TaintAnalysisOptions {
            include_inferred_sources: true,
            include_pattern_only: true,
            ..Default::default()
        },
    )
    .expect("analysis");
    let finding = report
        .findings
        .iter()
        .find(|finding| finding.finding.sink.rule_id == "python.test.source_independent_config")
        .unwrap_or_else(|| {
            panic!(
                "source-independent rule should emit only as pattern evidence when requested: {:#?}",
                report.findings
            )
        });
    assert_eq!(
        finding.finding.source.rule_id,
        "pattern:python.test.source_independent_config"
    );
    assert!(
        finding.finding.taint_path.is_empty(),
        "source-independent finding must not carry a fabricated taint path: {:#?}",
        finding.finding
    );
}

#[test]
fn lifecycle_audit_sink_does_not_emit_taint_or_pattern_findings() {
    let ws = workspace(
        "app.py",
        r#"
def handler(user_input, conn):
    conn.commit()
    return user_input
"#,
    );
    let mut sink = call_regex_rule(
        "python",
        "python.test.lifecycle_audit_commit",
        "race",
        r"^[A-Za-z_$][A-Za-z0-9_$]*\.commit$",
    );
    sink.category = Some("lifecycle-audit".to_string());
    let pack = pack_for("python", vec![sink]);

    let report = run_taint_analysis(
        &ws,
        &pack,
        TaintAnalysisOptions {
            include_inferred_sources: true,
            include_pattern_only: true,
            ..Default::default()
        },
    )
    .expect("analysis");
    assert!(
        report.findings.is_empty(),
        "lifecycle-audit rules are matcher/audit evidence only, not taint or pattern findings: {:#?}",
        report.findings
    );
}

#[test]
fn taint_constrained_sink_does_not_report_without_taint() {
    let ws = workspace(
        "app.py",
        r#"
def handler():
    dangerous("safe")
"#,
    );
    let mut sink = call_name_rule(
        "python",
        "python.test.dangerous_arg",
        "command-injection",
        "dangerous",
    );
    sink.constraints = RuleConstraint(vec![ConstraintKind::ArgTainted {
        arg_tainted: ArgTaintedSpec {
            index: Some(0),
            kw: None,
        },
    }]);
    let pack = pack_for("python", vec![sink]);

    let report = run_taint_analysis(
        &ws,
        &pack,
        TaintAnalysisOptions {
            include_pattern_only: true,
            ..Default::default()
        },
    )
    .expect("analysis");
    assert!(report.findings.is_empty(), "{:#?}", report.findings);
}

#[test]
fn pattern_only_constraints_are_enforced() {
    let ws = workspace(
        "App.java",
        r#"
class App {
    void weak() throws Exception {
        Cipher.getInstance("DES");
    }
    void strong() throws Exception {
        Cipher.getInstance("AES/GCM/NoPadding");
    }
}
"#,
    );
    let mut sink = call_attr_rule(
        "java",
        "java.test.cipher_des",
        "weak-crypto",
        &["Cipher", "getInstance"],
    );
    sink.category = Some("source-independent".to_string());
    sink.constraints = RuleConstraint(vec![ConstraintKind::ArgMatchesRegex {
        arg_matches_regex: ArgRegexSpec {
            index: 0,
            regex: r#"^"DES"$"#.to_string(),
        },
    }]);
    let pack = pack_for("java", vec![sink]);

    let report = run_taint_analysis(
        &ws,
        &pack,
        TaintAnalysisOptions {
            include_pattern_only: true,
            ..Default::default()
        },
    )
    .expect("analysis");
    let hits: Vec<_> = report
        .findings
        .iter()
        .filter(|finding| finding.finding.sink.rule_id == "java.test.cipher_des")
        .collect();
    assert_eq!(hits.len(), 1, "{:#?}", report.findings);
}

#[test]
fn pattern_only_and_taint_same_site_emits_once() {
    let ws = workspace(
        "app.py",
        r#"
def handler(user_input):
    dangerous(user_input)
"#,
    );
    let pack = pack_for(
        "python",
        vec![call_name_rule(
            "python",
            "python.test.pattern_dangerous",
            "weak-crypto",
            "dangerous",
        )],
    );

    let report = run_taint_analysis(
        &ws,
        &pack,
        TaintAnalysisOptions {
            include_inferred_sources: true,
            include_pattern_only: true,
            ..Default::default()
        },
    )
    .expect("analysis");
    let hits: Vec<_> = report
        .findings
        .iter()
        .filter(|finding| finding.finding.sink.rule_id == "python.test.pattern_dangerous")
        .collect();
    assert_eq!(hits.len(), 1, "{:#?}", report.findings);
}

#[test]
fn processbuilder_start_reports_after_tainted_command_list() {
    let ws = workspace(
        "App.java",
        r"
import java.util.ArrayList;

class App {
    void handle(String input) throws Exception {
        ArrayList<String> argList = new ArrayList<>();
        argList.add(input);
        ProcessBuilder pb = new ProcessBuilder();
        pb.command(argList);
        pb.start();
    }
}
",
    );
    let mut list_add = call_attr_rule(
        "java",
        "java.test.list_add_mutator",
        "test-mutator",
        &["ArrayList", "add"],
    );
    list_add.constraints = RuleConstraint(vec![ConstraintKind::ArgTainted {
        arg_tainted: ArgTaintedSpec {
            index: Some(0),
            kw: None,
        },
    }]);
    list_add.taint_semantics = Some(TaintSemantics {
        clean_output_overwrite: None,
        source_output_args: Vec::new(),
        source_callback_args: Vec::new(),
        call_result_passthrough_args: Vec::new(),
        call_result_passthrough_receiver: false,
        output_arg_flows: Vec::new(),
        taint_receiver_from_args: true,
    });
    let mut command = call_attr_rule(
        "java",
        "java.test.processbuilder_command",
        "command-injection",
        &["ProcessBuilder", "command"],
    );
    command.constraints = RuleConstraint(vec![ConstraintKind::ArgTainted {
        arg_tainted: ArgTaintedSpec {
            index: Some(0),
            kw: None,
        },
    }]);
    command.taint_semantics = Some(TaintSemantics {
        clean_output_overwrite: None,
        source_output_args: Vec::new(),
        source_callback_args: Vec::new(),
        call_result_passthrough_args: Vec::new(),
        call_result_passthrough_receiver: false,
        output_arg_flows: Vec::new(),
        taint_receiver_from_args: true,
    });
    let mut start = call_attr_rule(
        "java",
        "java.test.processbuilder_start",
        "command-injection",
        &["ProcessBuilder", "start"],
    );
    start.constraints = RuleConstraint(vec![ConstraintKind::ReceiverTainted {
        receiver_tainted: true,
    }]);
    let pack = pack_for("java", vec![list_add, command, start]);

    let report = run_taint_analysis(
        &ws,
        &pack,
        TaintAnalysisOptions {
            include_inferred_sources: true,
            ..Default::default()
        },
    )
    .expect("analysis");
    assert!(
        report
            .findings
            .iter()
            .any(|finding| finding.finding.sink.rule_id == "java.test.processbuilder_start"),
        "tainted list element should flow through command(argList) into pb.start(); findings={:#?}",
        report.findings
    );
}

#[test]
fn java_constructor_receiver_dispatch_uses_caller_context_in_taint() {
    let ws = workspace_multi(&[
        (
            "app/Controller.java",
            r#"
package app;

class Controller {
    void handle(String input) throws Exception {
        Service svc = new Service();
        svc.process(input);
    }
}
"#,
        ),
        (
            "app/Service.java",
            r#"
package app;

class Service {
    void process(String cmd) throws Exception {
        Runtime.getRuntime().exec(cmd);
    }
}
"#,
        ),
        (
            "aaa/Service.java",
            r#"
package aaa;

class Service {
    void process(String cmd) throws Exception {
        safe(cmd);
    }
    void safe(String value) {}
}
"#,
        ),
    ]);
    let mut sink = call_regex_rule(
        "java",
        "java.test.runtime_exec",
        "command-injection",
        r"(^|[.])exec$",
    );
    sink.constraints = RuleConstraint(vec![ConstraintKind::ArgTainted {
        arg_tainted: ArgTaintedSpec {
            index: Some(0),
            kw: None,
        },
    }]);
    let pack = pack_for("java", vec![sink]);

    let report = run_taint_analysis(
        &ws,
        &pack,
        TaintAnalysisOptions {
            include_inferred_sources: true,
            ..Default::default()
        },
    )
    .expect("analysis");
    let hits: Vec<_> = report
        .findings
        .iter()
        .filter(|finding| finding.finding.sink.rule_id == "java.test.runtime_exec")
        .collect();
    assert_eq!(hits.len(), 1, "{:#?}", report.findings);
    assert!(
        hits[0].finding.sink.file.ends_with("app/Service.java"),
        "taint must dispatch to app.Service.process, not aaa.Service.process: {:#?}",
        report.findings
    );
}
