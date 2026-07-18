use bonsai_lang_api::LanguageRegistry;
use bonsai_security::loader::LanguagePack;
use bonsai_security::{
    build_inventory, MatchKind, MatchSpec, Rule, RuleConstraint, RuleKind, RuleTarget, Rulepack, Severity,
};
use bonsai_workspace::Workspace;
use std::sync::Arc;

fn temp_root(tag: &str) -> std::path::PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("time")
        .as_nanos();
    let path = std::env::temp_dir().join(format!("{tag}-{}-{nanos}", std::process::id()));
    std::fs::create_dir(&path).expect("temp dir");
    path
}

fn package_rule(package: &str) -> Rule {
    Rule {
        id: "java.test.package_gate".to_string(),
        aliases: Vec::new(),
        enabled: true,
        disabled_reason: None,
        title: None,
        tag: Some("test".to_string()),
        severity: Some(Severity::Critical),
        trust: None,
        category: None,
        cwe: vec![],
        owasp: vec![],
        frameworks: vec![],
        packages: vec![package.to_string()],
        imports: vec![],
        modules: vec![],
        manifests: vec![],
        lockfiles: vec![],
        payload_types: vec![],
        match_spec: MatchSpec {
            kind: MatchKind::Call,
            callee: Some(RuleTarget {
                name: Some("lookup".to_string()),
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
        description: "test".to_string(),
        kind: RuleKind::Sink,
        language: "java".to_string(),
        source_path: "test.yml".to_string(),
    }
}

#[test]
fn dependency_inventory_scans_deep_workspace_manifests() {
    let root = temp_root("bonsai-deps-package-deep");
    let manifest_dir = root
        .join("services")
        .join("payments")
        .join("src")
        .join("main")
        .join("resources")
        .join("module");
    std::fs::create_dir_all(&manifest_dir).expect("deep manifest dir");
    std::fs::write(
        manifest_dir.join("pom.xml"),
        r"<project><artifactId>log4j-core</artifactId></project>",
    )
    .expect("deep pom");

    let mut pack = Rulepack::default();
    pack.packs.insert(
        "java".to_string(),
        LanguagePack {
            language: "java".to_string(),
            sources: Vec::new(),
            sinks: vec![package_rule("log4j-core")],
            sanitizers: Vec::new(),
            typing: Vec::new(),
        },
    );

    let ws = Workspace::new(Arc::new(LanguageRegistry::new()));
    let inventory = build_inventory(&pack, &ws, &root);
    assert!(
        inventory.rows.iter().any(|row| {
            row.key == "log4j-core"
                && row.signals.iter().any(|signal| signal == "packages:log4j-core")
                && row
                    .evidence_files
                    .iter()
                    .any(|file| file.ends_with("module/pom.xml"))
        }),
        "expected deep log4j-core manifest evidence, got {:?}",
        inventory.rows
    );

    std::fs::remove_dir_all(&root).ok();
}
