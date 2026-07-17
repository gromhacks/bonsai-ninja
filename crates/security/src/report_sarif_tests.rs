use super::*;
use crate::finding::{
    Finding, FindingMatch, FindingStatus, TaintPropagationArg, TaintPropagationStep, TaintedArgInfo,
};
use crate::rule::Severity;
use serde_json::Value;

fn sample_match(rule_id: &str, file: &str, line: u32) -> FindingMatch {
    FindingMatch {
        rule_id: rule_id.to_string(),
        file: file.to_string(),
        line,
        column: 5,
        text: format!("call site for {rule_id}"),
        enclosing_fn: Some("handle_request".to_string()),
        tag: Some("command-injection".to_string()),
        severity: Some(Severity::Critical),
        category: None,
        trust: Some("remote".to_string()),
        payload_types: Vec::new(),
        tainted_args: vec![TaintedArgInfo {
            index: 0,
            value_text: "user_input".to_string(),
            ..TaintedArgInfo::default()
        }],
        sanitised_arg_indices: Vec::new(),
    }
}

fn sample_finding() -> Finding {
    Finding {
        finding_id: "S:00000000abcd1234".to_string(),
        language: "python".to_string(),
        source: sample_match("python.sources.flask_args", "app.py", 12),
        sink: sample_match("python.cmdi.os_system", "auth.py", 42),
        sanitizers_seen: Vec::new(),
        group_id: Some("G:000000000a1b2c3d".to_string()),
        representative_flow_id: Some("F:0000000001ab73e2".to_string()),
        analysis_complete: true,
        analysis_incomplete_reasons: Vec::new(),
        chain_display: vec![
            "handle_request".to_string(),
            "verify_token".to_string(),
            "run_admin_command".to_string(),
        ],
        taint_path: Vec::new(),
        hops: Vec::new(),
        tag: Some("command-injection".to_string()),
        severity: Some(Severity::Critical),
        precision: "exact".to_string(),
        cwe: vec!["CWE-78".to_string()],
        owasp: vec!["A03".to_string()],
        status: FindingStatus::Unsanitized,
        from_test: false,
    }
}

fn temp_root(tag: &str) -> std::path::PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time")
        .as_nanos();
    let path = std::env::temp_dir().join(format!("{tag}-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&path).expect("create temp root");
    path
}

#[test]
fn sarif_render_top_level_shape() {
    let report = SecurityReport::new(vec![sample_finding()]).with_analysis_completeness(true, Vec::new());
    let s = render_sarif_json(&report);
    let v: Value = serde_json::from_str(&s).expect("valid json");
    assert_eq!(v["version"], "2.1.0");
    assert!(v["$schema"].as_str().unwrap().contains("sarif-schema-2.1.0"));
    assert_eq!(v["runs"][0]["tool"]["driver"]["name"], "bonsai-ninja");
    assert_eq!(v["runs"][0]["columnKind"], "utf16CodeUnits");
    assert_eq!(v["runs"][0]["invocations"][0]["executionSuccessful"], true);
    // S2: rules[] now contains one entry per loaded sink rule
    // (the bonsai rule the finding fired on), not the CWE.
    let rules = v["runs"][0]["tool"]["driver"]["rules"].as_array().unwrap();
    assert!(
        rules.iter().any(|r| r["id"] == "python.cmdi.os_system"),
        "rules[] should contain the sink rule id, got {rules:#?}"
    );
    // S6: CWE classification lives in runs[].taxonomies, not in
    // tool.driver.rules.
    assert_eq!(v["runs"][0]["taxonomies"][0]["name"], "CWE");
    assert_eq!(v["runs"][0]["taxonomies"][0]["guid"], CWE_TAXONOMY_GUID);
    assert_eq!(
        v["runs"][0]["tool"]["driver"]["supportedTaxonomies"][0]["guid"],
        CWE_TAXONOMY_GUID
    );
    assert!(v["runs"][0]["taxonomies"][0]["taxa"]
        .as_array()
        .unwrap()
        .iter()
        .any(|t| t["id"] == "CWE-78"));
}

#[test]
fn sarif_does_not_report_success_for_incomplete_semantic_coverage() {
    let report = SecurityReport::new(Vec::new())
        .with_analysis_completeness(false, vec!["unresolved-workspace-call-sites:2".to_string()]);
    let value: Value = serde_json::from_str(&render_sarif_json(&report)).expect("valid SARIF");
    let invocation = &value["runs"][0]["invocations"][0];
    assert_eq!(invocation["executionSuccessful"], false);
    assert_eq!(invocation["properties"]["bonsai"]["analysis_complete"], false);
    assert!(invocation["toolExecutionNotifications"][0]["message"]["text"]
        .as_str()
        .is_some_and(|message| message.contains("unresolved-workspace-call-sites:2")));
}

#[test]
fn train_renderer_preserves_empty_report_completeness_metadata() {
    let report = SecurityReport::with_runtime_disabled_rules(
        Vec::new(),
        vec![RuntimeDisabledRule {
            rule_id: "python.test.rule".to_string(),
            reason: "runtime matcher preparation failed".to_string(),
        }],
    )
    .with_analysis_completeness(false, vec!["unresolved-workspace-call-sites:2".to_string()]);
    let value: Value = serde_json::from_str(&render_train_json(&report)).expect("valid train JSON");

    assert_eq!(value["examples"], serde_json::json!([]));
    assert_eq!(value["analysis_complete"], false);
    assert_eq!(
        value["analysis_incomplete_reasons"],
        serde_json::json!(["unresolved-workspace-call-sites:2"])
    );
    assert_eq!(value["runtime_disabled_rules"][0]["rule_id"], "python.test.rule");
}

#[test]
fn grouped_text_distinguishes_complete_and_incomplete_empty_reports() {
    let complete = SecurityReport::new(Vec::new()).with_analysis_completeness(true, Vec::new());
    let complete_text = render_grouped_text(&complete);
    assert!(complete_text.contains("0 finding(s)"));
    assert!(complete_text.contains("analysis: complete"));

    let incomplete = SecurityReport::new(Vec::new())
        .with_analysis_completeness(false, vec!["parse-timeout:src/app.py".to_string()]);
    let incomplete_text = render_grouped_text(&incomplete);
    assert!(incomplete_text.contains("analysis: incomplete"));
    assert!(incomplete_text.contains("parse-timeout:src/app.py"));
}

#[test]
fn sarif_result_rule_id_is_bonsai_sink_rule() {
    // S1: ruleId is the bonsai rule that fired, not the CWE.
    // GitHub code-scanning groups by ruleId; using the sink rule
    // gives us per-rule baselines and suppressions.
    let report = SecurityReport::new(vec![sample_finding()]);
    let s = render_sarif_json(&report);
    let v: Value = serde_json::from_str(&s).unwrap();
    let result = &v["runs"][0]["results"][0];
    assert_eq!(result["ruleId"], "python.cmdi.os_system");
    assert_eq!(result["level"], "error");
    // S3: ruleIndex points into tool.driver.rules[].
    assert_eq!(result["ruleIndex"], 0);
}

#[test]
fn sarif_result_carries_kind_rank_fingerprints() {
    // S5 + S7: kind/rank for IDE sorting; fingerprints for CI
    // baseline diffing.
    let report = SecurityReport::new(vec![sample_finding()]);
    let s = render_sarif_json(&report);
    let v: Value = serde_json::from_str(&s).unwrap();
    let result = &v["runs"][0]["results"][0];
    assert_eq!(result["kind"], "fail");
    assert!(result["rank"].as_f64().unwrap() >= 90.0);
    assert_eq!(result["fingerprints"]["bonsai/finding/v1"], "S:00000000abcd1234");
    assert!(result["partialFingerprints"]["bonsai/source-sink-host/v1"]
        .as_str()
        .unwrap()
        .contains("python.cmdi.os_system"));
    assert_eq!(
        result["partialFingerprints"]["primaryLocationStartColumnFingerprint"],
        "5"
    );
    assert!(result["partialFingerprints"]["primaryLocationLineHash"]
        .as_str()
        .unwrap()
        .ends_with(":1"));
}

#[test]
fn sarif_taxa_link_each_finding_to_its_cwe() {
    // S6: CWE on the result via SARIF's reportingDescriptorReference shape.
    let report = SecurityReport::new(vec![sample_finding()]);
    let s = render_sarif_json(&report);
    let v: Value = serde_json::from_str(&s).unwrap();
    let taxa = &v["runs"][0]["results"][0]["taxa"];
    let arr = taxa.as_array().expect("taxa array");
    assert!(!arr.is_empty(), "expected at least one taxa reference");
    assert_eq!(arr[0]["id"], "CWE-78");
    assert_eq!(arr[0]["toolComponent"]["name"], "CWE");
    assert_eq!(arr[0]["toolComponent"]["guid"], CWE_TAXONOMY_GUID);
}

#[test]
fn sarif_review_kind_for_sanitized_findings() {
    let mut f = sample_finding();
    f.status = FindingStatus::Sanitized;
    let report = SecurityReport::new(vec![f]);
    let s = render_sarif_json(&report);
    let v: Value = serde_json::from_str(&s).unwrap();
    assert_eq!(v["runs"][0]["results"][0]["kind"], "review");
}

#[test]
fn sarif_severity_maps_to_sarif_level() {
    let levels = [
        (Severity::Critical, "error"),
        (Severity::High, "error"),
        (Severity::Medium, "warning"),
        (Severity::Low, "note"),
        (Severity::Info, "note"),
    ];
    for (sev, expected_level) in levels {
        let mut f = sample_finding();
        f.severity = Some(sev);
        f.sink.severity = Some(sev);
        let report = SecurityReport::new(vec![f]);
        let s = render_sarif_json(&report);
        let v: Value = serde_json::from_str(&s).unwrap();
        assert_eq!(
            v["runs"][0]["results"][0]["level"], expected_level,
            "severity {sev:?} should map to SARIF level {expected_level}"
        );
    }
}

#[test]
fn sarif_location_uses_sink_file_line_column() {
    let report = SecurityReport::new(vec![sample_finding()]);
    let s = render_sarif_json(&report);
    let v: Value = serde_json::from_str(&s).unwrap();
    let loc = &v["runs"][0]["results"][0]["locations"][0];
    // S8: without workspace_root, paths fall back to absolute
    // (no uriBaseId emitted).
    assert_eq!(loc["physicalLocation"]["artifactLocation"]["uri"], "auth.py");
    assert!(loc["physicalLocation"]["artifactLocation"]["uriBaseId"].is_null());
    let region = &loc["physicalLocation"]["region"];
    assert_eq!(region["startLine"], 42);
    assert_eq!(region["startColumn"], 5);
    // S9: endLine/endColumn/snippet now emitted so IDEs can
    // highlight the exact expression.
    assert_eq!(region["endLine"], 42);
    assert!(region["endColumn"].as_u64().unwrap() > 5);
    assert!(
        region["snippet"]["text"]
            .as_str()
            .unwrap()
            .contains("python.cmdi.os_system"),
        "snippet should carry the matched text"
    );
    let logical = &loc["logicalLocations"][0];
    assert_eq!(logical["name"], "handle_request");
    assert_eq!(logical["kind"], "function");
    assert_eq!(logical["fullyQualifiedName"], "auth.py::handle_request");
}

#[test]
fn sarif_paths_relative_when_workspace_root_supplied() {
    // S8: with workspace_root the paths are relative under
    // %SRCROOT%, no host paths leaked.
    let mut f = sample_finding();
    f.sink.file = "/projects/x/auth.py".to_string();
    f.source.file = "/projects/x/app.py".to_string();
    let report = SecurityReport::new(vec![f]);
    let s = render_sarif_with_provenance(&report, Some("/projects/x"), None);
    let v: Value = serde_json::from_str(&s).unwrap();
    assert_eq!(
        v["runs"][0]["originalUriBaseIds"]["%SRCROOT%"]["uri"],
        "file:///projects/x/"
    );
    let sink_loc = &v["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"];
    assert_eq!(sink_loc["uri"], "auth.py");
    assert_eq!(sink_loc["uriBaseId"], "%SRCROOT%");
}

#[cfg(unix)]
#[test]
fn sarif_paths_relative_when_file_reaches_workspace_through_symlink() {
    use std::os::unix::fs::symlink;

    let root = temp_root("bonsai-sarif-symlink");
    std::fs::write(root.join("auth.py"), "os.system(cmd)\n").expect("write auth");
    std::fs::write(root.join("app.py"), "request.args['cmd']\n").expect("write app");
    let link = root.with_file_name(format!(
        "{}-link",
        root.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("bonsai-sarif")
    ));
    let _ = std::fs::remove_file(&link);
    symlink(&root, &link).expect("symlink workspace");

    let mut f = sample_finding();
    f.sink.file = link.join("auth.py").to_string_lossy().to_string();
    f.source.file = link.join("app.py").to_string_lossy().to_string();
    let report = SecurityReport::new(vec![f]);
    let workspace_root = root
        .canonicalize()
        .expect("canonical root")
        .to_string_lossy()
        .to_string();
    let s = render_sarif_with_provenance(&report, Some(&workspace_root), None);
    let v: Value = serde_json::from_str(&s).unwrap();
    let sink_loc = &v["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"];

    assert_eq!(sink_loc["uri"], "auth.py");
    assert_eq!(sink_loc["uriBaseId"], "%SRCROOT%");
    assert!(
        !sink_loc["uri"]
            .as_str()
            .unwrap()
            .contains(root.to_string_lossy().as_ref()),
        "SARIF artifact uri should not leak the host workspace path: {sink_loc:#?}"
    );

    let _ = std::fs::remove_file(link);
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn sarif_codeflows_threads_source_then_sink() {
    // S4: every step carries `kinds: [...]` for IDE
    // step-through labelling.
    let report = SecurityReport::new(vec![sample_finding()]);
    let s = render_sarif_json(&report);
    let v: Value = serde_json::from_str(&s).unwrap();
    let tflows = &v["runs"][0]["results"][0]["codeFlows"][0]["threadFlows"][0]["locations"];
    let arr = tflows.as_array().unwrap();
    assert_eq!(arr.len(), 2);
    assert_eq!(arr[0]["kinds"][0], "source");
    assert_eq!(arr[1]["kinds"][0], "sink");
    assert_eq!(
        arr[0]["location"]["physicalLocation"]["artifactLocation"]["uri"],
        "app.py"
    );
    assert_eq!(
        arr[1]["location"]["physicalLocation"]["artifactLocation"]["uri"],
        "auth.py"
    );
}

#[test]
fn sarif_codeflows_includes_sanitizer_hops_in_path_order() {
    let mut f = sample_finding();
    f.taint_path = vec![
        TaintPropagationStep {
            caller: "handle_request".to_string(),
            callee: "normalize".to_string(),
            file: "app.py".to_string(),
            line: 20,
            column: 9,
            tainted_args: Vec::new(),
        },
        TaintPropagationStep {
            caller: "normalize".to_string(),
            callee: "run_admin_command".to_string(),
            file: "lib.py".to_string(),
            line: 8,
            column: 5,
            tainted_args: Vec::new(),
        },
        TaintPropagationStep {
            caller: "run_admin_command".to_string(),
            callee: "os.system".to_string(),
            file: "auth.py".to_string(),
            line: 42,
            column: 5,
            tainted_args: Vec::new(),
        },
    ];
    f.sanitizers_seen = vec![sample_match("python.sanitizers.shlex_quote", "lib.py", 8)];
    let report = SecurityReport::new(vec![f]);
    let s = render_sarif_json(&report);
    let v: Value = serde_json::from_str(&s).unwrap();
    let tflows = &v["runs"][0]["results"][0]["codeFlows"][0]["threadFlows"][0]["locations"];
    let arr = tflows.as_array().unwrap();
    assert_eq!(arr.len(), 5);
    assert_eq!(arr[0]["kinds"][0], "source");
    assert_eq!(arr[1]["kinds"][0], "taint");
    assert_eq!(arr[2]["kinds"][0], "taint");
    assert_eq!(arr[3]["kinds"][0], "sanitizer");
    assert_eq!(
        arr[3]["location"]["physicalLocation"]["artifactLocation"]["uri"],
        "lib.py"
    );
    assert_eq!(arr[4]["kinds"][0], "sink");
}

#[test]
fn sarif_pattern_findings_skip_codeflows() {
    let mut f = sample_finding();
    f.source.category = Some("pattern".to_string());
    f.source.rule_id = "pattern:python.weakrand.random".to_string();
    f.source.file = f.sink.file.clone();
    f.source.line = f.sink.line;
    f.source.column = f.sink.column;
    f.taint_path = Vec::new();
    let report = SecurityReport::new(vec![f]);
    let s = render_sarif_json(&report);
    let v: Value = serde_json::from_str(&s).unwrap();
    assert!(
        v["runs"][0]["results"][0]["codeFlows"].is_null(),
        "pattern-only results should not fabricate source==sink codeFlows"
    );
}

#[test]
fn sarif_codeflows_include_concrete_taint_path_hops() {
    let mut f = sample_finding();
    f.taint_path = vec![TaintPropagationStep {
        caller: "handle_request".to_string(),
        callee: "run_admin_command".to_string(),
        file: "app.py".to_string(),
        line: 20,
        column: 9,
        tainted_args: vec![TaintPropagationArg {
            index: 0,
            value_text: "payload".to_string(),
            param_name: "cmd".to_string(),
        }],
    }];
    let report = SecurityReport::new(vec![f]);
    let s = render_sarif_json(&report);
    let v: Value = serde_json::from_str(&s).unwrap();
    let tflows = &v["runs"][0]["results"][0]["codeFlows"][0]["threadFlows"][0]["locations"];
    let arr = tflows.as_array().unwrap();
    assert_eq!(arr.len(), 3);
    assert_eq!(arr[0]["kinds"][0], "source");
    assert_eq!(arr[1]["kinds"][0], "taint");
    assert_eq!(arr[1]["kinds"][1], "call");
    assert_eq!(
        arr[1]["location"]["physicalLocation"]["artifactLocation"]["uri"],
        "app.py"
    );
    assert_eq!(arr[1]["location"]["physicalLocation"]["region"]["startLine"], 20);
    assert_eq!(
        arr[1]["location"]["properties"]["tainted_args"][0]["param_name"],
        "cmd"
    );
    assert_eq!(arr[2]["kinds"][0], "sink");
}

#[test]
fn sarif_codeflows_collapse_adjacent_same_line_locations() {
    let mut f = sample_finding();
    f.source.file = "app.py".to_string();
    f.source.line = 20;
    f.source.column = 5;
    f.sink.file = "app.py".to_string();
    f.sink.line = 20;
    f.sink.column = 27;
    f.taint_path = vec![
        TaintPropagationStep {
            caller: "handle_request".to_string(),
            callee: "normalize".to_string(),
            file: "app.py".to_string(),
            line: 20,
            column: 9,
            tainted_args: Vec::new(),
        },
        TaintPropagationStep {
            caller: "normalize".to_string(),
            callee: "os.system".to_string(),
            file: "app.py".to_string(),
            line: 20,
            column: 27,
            tainted_args: Vec::new(),
        },
    ];
    let report = SecurityReport::new(vec![f]);
    let s = render_sarif_json(&report);
    let v: Value = serde_json::from_str(&s).unwrap();
    let tflows = &v["runs"][0]["results"][0]["codeFlows"][0]["threadFlows"][0]["locations"];
    let arr = tflows.as_array().unwrap();
    assert_eq!(arr.len(), 1);
    let kinds = arr[0]["kinds"].as_array().unwrap();
    assert!(kinds.iter().any(|kind| kind == "source"));
    assert!(kinds.iter().any(|kind| kind == "sink"));
}

#[test]
fn sarif_rule_descriptors_carry_cwe_metadata() {
    let report = SecurityReport::new(vec![sample_finding()]);
    let s = render_sarif_json(&report);
    let v: Value = serde_json::from_str(&s).unwrap();
    let rule = &v["runs"][0]["tool"]["driver"]["rules"][0];
    assert_eq!(rule["id"], "python.cmdi.os_system");
    assert_eq!(
        rule["messageStrings"]["default"]["text"],
        "Tainted value reaches python.cmdi.os_system from {0}."
    );
    assert_eq!(rule["defaultConfiguration"]["enabled"], true);
    assert!(rule["defaultConfiguration"]["rank"].as_f64().unwrap() >= 90.0);
    assert_eq!(rule["properties"]["cwe"][0], "CWE-78");
    assert_eq!(rule["properties"]["security-severity"], "9.5");
    assert_eq!(rule["properties"]["precision"], "high");
    assert_eq!(rule["relationships"][0]["target"]["id"], "CWE-78");
    assert_eq!(
        rule["relationships"][0]["target"]["toolComponent"]["guid"],
        CWE_TAXONOMY_GUID
    );
}

#[test]
fn sarif_dedups_sanitizer_rule_ids() {
    // S11: same sanitizer matched on multiple args produces
    // duplicate FindingMatch entries with the same rule_id;
    // the SARIF emit dedups them.
    let mut f = sample_finding();
    let m = sample_match("python.sanitizer.bleach_clean", "lib.py", 8);
    f.sanitizers_seen = vec![m.clone(), m];
    let report = SecurityReport::new(vec![f]);
    let s = render_sarif_json(&report);
    let v: Value = serde_json::from_str(&s).unwrap();
    let ids = v["runs"][0]["results"][0]["properties"]["bonsai"]["sanitizer_rule_ids"]
        .as_array()
        .unwrap();
    assert_eq!(ids.len(), 1);
    assert_eq!(ids[0], "python.sanitizer.bleach_clean");
}

#[test]
fn sarif_properties_carry_bonsai_metadata() {
    let report = SecurityReport::new(vec![sample_finding()]);
    let s = render_sarif_json(&report);
    let v: Value = serde_json::from_str(&s).unwrap();
    let props = &v["runs"][0]["results"][0]["properties"]["bonsai"];
    assert_eq!(props["finding_id"], "S:00000000abcd1234");
    assert_eq!(props["flow_id"], "F:0000000001ab73e2");
    assert_eq!(props["group_id"], "G:000000000a1b2c3d");
    assert_eq!(props["language"], "python");
    assert_eq!(props["status"], "unsanitized");
    assert_eq!(props["cwe"][0], "CWE-78");
    assert_eq!(props["chain_display"][0], "handle_request");
    assert_eq!(props["tainted_args"][0]["value_text"], "user_input");
}

#[test]
fn sarif_empty_report_emits_well_formed_run_with_empty_results() {
    let report = SecurityReport::new(Vec::new());
    let s = render_sarif_json(&report);
    let v: Value = serde_json::from_str(&s).unwrap();
    assert_eq!(v["runs"][0]["results"].as_array().unwrap().len(), 0);
    assert_eq!(v["runs"][0]["tool"]["driver"]["name"], "bonsai-ninja");
    assert!(v["runs"][0]["tool"]["driver"]["rules"]
        .as_array()
        .unwrap()
        .is_empty());
}

#[test]
fn sarif_emits_one_rule_per_distinct_sink_rule_id() {
    // S2: rules[] has one entry per loaded sink rule. Two
    // findings with different sink rule ids → two rule entries
    // even when they share a CWE.
    let f1 = sample_finding();
    let mut f2 = sample_finding();
    f2.finding_id = "S:0000000011111111".to_string();
    f2.sink = sample_match("python.cmdi.subprocess", "other.py", 99);
    let report = SecurityReport::new(vec![f1, f2]);
    let s = render_sarif_json(&report);
    let v: Value = serde_json::from_str(&s).unwrap();
    let rules = v["runs"][0]["tool"]["driver"]["rules"].as_array().unwrap();
    assert_eq!(rules.len(), 2);
    let ids: std::collections::HashSet<_> = rules
        .iter()
        .map(|r| r["id"].as_str().unwrap().to_string())
        .collect();
    assert!(ids.contains("python.cmdi.os_system"));
    assert!(ids.contains("python.cmdi.subprocess"));
    // ruleIndex on each result points back into rules[].
    let r0 = &v["runs"][0]["results"][0];
    let r1 = &v["runs"][0]["results"][1];
    let idx0 = r0["ruleIndex"].as_u64().unwrap() as usize;
    let idx1 = r1["ruleIndex"].as_u64().unwrap() as usize;
    assert_eq!(rules[idx0]["id"], r0["ruleId"]);
    assert_eq!(rules[idx1]["id"], r1["ruleId"]);
}

#[test]
fn sarif_emits_version_control_provenance_when_supplied() {
    // S10: optional VCS metadata for CI scan differentiation.
    let report = SecurityReport::new(vec![sample_finding()]);
    let s = render_sarif_with_provenance(
        &report,
        None,
        Some(("https://github.com/foo/bar", "main", "abc123")),
    );
    let v: Value = serde_json::from_str(&s).unwrap();
    let prov = &v["runs"][0]["versionControlProvenance"][0];
    assert_eq!(prov["repositoryUri"], "https://github.com/foo/bar");
    assert_eq!(prov["branch"], "main");
    assert_eq!(prov["revisionId"], "abc123");
    // automationDetails always present.
    assert_eq!(
        v["runs"][0]["automationDetails"]["id"],
        "bonsai-ninja/security/taint-analysis"
    );
}
