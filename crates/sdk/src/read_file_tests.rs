use super::*;
use bonsai_common::Precision;
use bonsai_security::{AlternateTaintFlow, MatchOrigin, TaintPropagationStep, TaintedArgInfo};

fn site(rule_id: &str, text: &str, enclosing_fn: &str) -> FindingMatch {
    FindingMatch {
        origin: MatchOrigin::Rulepack,
        rule_id: rule_id.to_string(),
        file: "app.py".to_string(),
        line: 1,
        column: 1,
        text: text.to_string(),
        enclosing_fn: Some(enclosing_fn.to_string()),
        tag: Some("command-injection".to_string()),
        severity: Some(Severity::High),
        category: None,
        trust: None,
        payload_types: Vec::new(),
        tainted_args: vec![TaintedArgInfo {
            index: 0,
            value_text: text.to_string(),
            ..TaintedArgInfo::default()
        }],
        sanitised_arg_indices: Vec::new(),
    }
}

fn combined() -> CombinedFindingWithChain {
    CombinedFindingWithChain {
        finding: Finding {
            finding_id: "S:1".to_string(),
            language: "python".to_string(),
            source: site("python.flask.request_args", "request.args", "handle_request"),
            sink: site("python.cmdi.os_system", "os.system(cmd)", "run_admin_command"),
            sanitizers_seen: Vec::new(),
            taint_transforms_seen: Vec::new(),
            group_id: Some("G:1".to_string()),
            representative_flow_id: Some("F:1".to_string()),
            analysis_complete: true,
            analysis_incomplete_reasons: Vec::new(),
            chain_display: vec![
                "handle_request".to_string(),
                "update_user".to_string(),
                "run_admin_command".to_string(),
            ],
            taint_path: vec![TaintPropagationStep {
                caller: "handle_request".to_string(),
                callee: "run_admin_command".to_string(),
                file: "app.py".to_string(),
                line: 2,
                column: 1,
                tainted_args: Vec::new(),
            }],
            alternate_flows: Vec::new(),
            hops: Vec::new(),
            tag: Some("command-injection".to_string()),
            severity: Some(Severity::High),
            precision: "exact".to_string(),
            cwe: Vec::new(),
            owasp: Vec::new(),
            status: FindingStatus::Unsanitized,
            from_test: false,
        },
        chain_funcs: Vec::new(),
        additional_sources: Vec::new(),
        additional_sinks: Vec::new(),
        member_finding_ids: Vec::new(),
    }
}

#[test]
fn zero_max_inlined_bodies_means_unbounded() {
    assert_eq!(effective_max_inlined_bodies(None), 8);
    assert_eq!(effective_max_inlined_bodies(Some(3)), 3);
    assert_eq!(effective_max_inlined_bodies(Some(0)), usize::MAX);
}

#[test]
fn read_file_from_to_filters_match_source_and_sink_sides() {
    let finding = combined();

    assert!(combined_finding_matches_filters(
        &finding,
        Some("request.args"),
        Some("os.system")
    ));
    assert!(combined_finding_matches_filters(
        &finding,
        Some("handle_request"),
        Some("run_admin_command")
    ));
    assert!(!combined_finding_matches_filters(
        &finding,
        Some("request.args"),
        Some("sql.query")
    ));
    assert!(!combined_finding_matches_filters(
        &finding,
        Some("cookie"),
        Some("os.system")
    ));
}

#[test]
fn read_file_filters_match_alternate_flow_sources_and_chains() {
    let mut finding = combined();
    finding.finding.alternate_flows.push(AlternateTaintFlow {
        source: site("python.flask.request_json", "request.json", "json_handler"),
        sink_tainted_args: finding.finding.sink.tainted_args.clone(),
        sanitizers_seen: Vec::new(),
        taint_transforms_seen: Vec::new(),
        flow_id: Some("F:2".to_string()),
        chain_display: vec!["json_handler".to_string(), "run_admin_command".to_string()],
        taint_path: vec![TaintPropagationStep {
            caller: "json_handler".to_string(),
            callee: "run_admin_command".to_string(),
            file: "app.py".to_string(),
            line: 3,
            column: 1,
            tainted_args: Vec::new(),
        }],
        status: FindingStatus::Unsanitized,
        precision: "exact".to_string(),
    });

    assert!(combined_finding_matches_filters(
        &finding,
        Some("request.json"),
        Some("run_admin_command")
    ));
    assert_eq!(finding.finding.flow_ids().collect::<Vec<_>>(), vec!["F:1", "F:2"]);
}

#[test]
fn finding_digest_uses_a_supported_stable_flow_drilldown() {
    let finding = combined().finding;
    let digest = build_finding_digest(&finding);
    assert_eq!(digest.drilldown, "bonsai-ninja show <ws> F:1");
}

#[test]
fn finding_digest_without_a_flow_uses_a_supported_file_drilldown() {
    let mut finding = combined().finding;
    finding.representative_flow_id = None;
    let digest = build_finding_digest(&finding);
    assert_eq!(digest.drilldown, "bonsai-ninja read-file <ws> app.py --lines 1:6");
}

#[test]
fn read_file_path_resolution_requires_path_boundary() {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "bonsai-read-file-path-boundary-{}-{stamp}",
        std::process::id()
    ));
    std::fs::create_dir(&root).expect("create temp dir");
    std::fs::write(root.join("myapp.py"), "def myapp_marker():\n    return 1\n").expect("write fixture");

    let ws = Workspace::index(&root, bonsai_adapters::all_languages_registry()).expect("index workspace");
    let err = read_file(
        &ws,
        None,
        &ReadFileFilters {
            path: "app.py",
            ..Default::default()
        },
    )
    .expect_err("app.py must not resolve to myapp.py by string suffix");
    assert!(
        err.to_string().contains("file not found in workspace"),
        "unexpected read-file error: {err}"
    );

    let out = read_file(
        &ws,
        None,
        &ReadFileFilters {
            path: "myapp.py",
            ..Default::default()
        },
    )
    .expect("exact file should resolve");
    assert!(out.source.contains("myapp_marker"));
    std::fs::remove_dir_all(&root).ok();
}

#[test]
fn read_file_taint_options_are_semantic_only() {
    let defaulted = semantic_read_file_taint_options(TaintAnalysisOptions::default());
    assert_eq!(defaulted.max_precision, Some(Precision::Narrowed));

    let exact = semantic_read_file_taint_options(TaintAnalysisOptions {
        max_precision: Some(Precision::Exact),
        ..Default::default()
    });
    assert_eq!(exact.max_precision, Some(Precision::Exact));

    let broad = semantic_read_file_taint_options(TaintAnalysisOptions {
        max_precision: Some(Precision::OverApproximate),
        ..Default::default()
    });
    assert_eq!(broad.max_precision, Some(Precision::Narrowed));
}

#[test]
fn read_file_propagates_taint_analysis_errors() {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "bonsai-read-file-taint-error-{}-{stamp}",
        std::process::id()
    ));
    std::fs::create_dir(&root).expect("create temp dir");
    std::fs::write(root.join("app.py"), "def handle(x):\n    return x\n").expect("write fixture");

    let ws = Workspace::index(&root, bonsai_adapters::all_languages_registry()).expect("index workspace");
    let pack = Rulepack::default();
    let err = read_file_with_taint_options(
        &ws,
        Some(&pack),
        &ReadFileFilters {
            path: "app.py",
            ..Default::default()
        },
        TaintAnalysisOptions {
            source: Some("[".to_string()),
            ..Default::default()
        },
    )
    .expect_err("invalid taint-analysis filter should fail read-file");
    assert!(
        err.to_string().contains("invalid rule regex"),
        "read-file must surface taint-analysis errors, got: {err}"
    );
    std::fs::remove_dir_all(&root).ok();
}
