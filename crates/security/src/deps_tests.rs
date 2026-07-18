use super::*;
use crate::loader::{LanguagePack, Rulepack};
use crate::rule::{MatchKind, MatchSpec, Rule, RuleConstraint, RuleKind, RuleTarget, Severity};

fn temp_root(tag: &str) -> std::path::PathBuf {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
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

fn python_package_rule(package: &str) -> Rule {
    let mut rule = package_rule(package);
    rule.id = "python.test.package_gate".to_string();
    rule.language = "python".to_string();
    rule
}

#[test]
fn dependency_inventory_treats_manifest_package_name_as_evidence() {
    let root = temp_root("bonsai-deps-package");
    std::fs::write(
        root.join("pom.xml"),
        r"<project><artifactId>log4j-core</artifactId></project>",
    )
    .expect("pom");
    let ws = Workspace::new(std::sync::Arc::new(bonsai_lang_api::LanguageRegistry::new()));

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

    let inventory = build_inventory(&pack, &ws, &root);
    assert!(
        inventory.rows.iter().any(|row| {
            row.key == "log4j-core"
                && row.signals.iter().any(|signal| signal == "packages:log4j-core")
                && row.evidence_files.iter().any(|file| file.ends_with("pom.xml"))
        }),
        "expected log4j-core manifest evidence, got {:?}",
        inventory.rows
    );
}

#[test]
fn dependency_inventory_does_not_project_one_package_signal_onto_siblings() {
    let root = temp_root("bonsai-deps-package-siblings");
    std::fs::write(
        root.join("pom.xml"),
        r"<project><artifactId>log4j-core</artifactId></project>",
    )
    .expect("pom");
    let ws = Workspace::new(std::sync::Arc::new(bonsai_lang_api::LanguageRegistry::new()));

    let mut rule = package_rule("log4j-core");
    rule.packages.push("commons-io".to_string());

    let mut pack = Rulepack::default();
    pack.packs.insert(
        "java".to_string(),
        LanguagePack {
            language: "java".to_string(),
            sources: Vec::new(),
            sinks: vec![rule],
            sanitizers: Vec::new(),
            typing: Vec::new(),
        },
    );

    let inventory = build_inventory(&pack, &ws, &root);
    assert!(
        inventory.rows.iter().any(|row| row.key == "log4j-core"),
        "expected log4j-core evidence, got {:?}",
        inventory.rows
    );
    assert!(
        inventory.rows.iter().all(|row| row.key != "commons-io"),
        "did not expect commons-io evidence from a log4j-core manifest, got {:?}",
        inventory.rows
    );
}

#[test]
fn workspace_dependency_packages_alias_python_distribution_names_to_imports() {
    let root = temp_root("bonsai-deps-python-aliases");
    std::fs::write(
        root.join("requirements.txt"),
        "psycopg2-binary==2.9.9\ndjangorestframework==3.15.1\nmysql-connector-python==9.1.0\n",
    )
    .expect("requirements");

    let packages = workspace_dependency_packages_for_language(&root, "python").packages;
    assert!(
        packages.contains("psycopg2"),
        "expected psycopg2 alias from psycopg2-binary, got {:?}",
        packages
    );
    assert!(
        packages.contains("rest_framework"),
        "expected rest_framework alias from djangorestframework, got {:?}",
        packages
    );
    assert!(
        packages.contains("mysql.connector"),
        "expected mysql.connector alias from mysql-connector-python, got {:?}",
        packages
    );
}

#[test]
fn workspace_dependency_packages_alias_rust_hyphenated_crates_to_imports() {
    let root = temp_root("bonsai-deps-rust-aliases");
    std::fs::write(
        root.join("Cargo.toml"),
        r#"[dependencies]
percent-encoding = "2"
"#,
    )
    .expect("cargo");

    let packages = workspace_dependency_packages_for_language(&root, "rust").packages;
    assert!(
        packages.contains("percent_encoding"),
        "expected percent_encoding alias from percent-encoding, got {:?}",
        packages
    );
}

#[test]
fn dependency_inventory_reports_python_distribution_alias_as_package_evidence() {
    let root = temp_root("bonsai-deps-python-inventory-alias");
    std::fs::write(root.join("requirements.txt"), "psycopg2-binary==2.9.9\n").expect("requirements");
    let ws = Workspace::new(std::sync::Arc::new(bonsai_lang_api::LanguageRegistry::new()));

    let mut pack = Rulepack::default();
    pack.packs.insert(
        "python".to_string(),
        LanguagePack {
            language: "python".to_string(),
            sources: Vec::new(),
            sinks: vec![python_package_rule("psycopg2")],
            sanitizers: Vec::new(),
            typing: Vec::new(),
        },
    );

    let inventory = build_inventory(&pack, &ws, &root);
    assert!(
        inventory.rows.iter().any(|row| {
            row.key == "psycopg2"
                && row.signals.iter().any(|signal| signal == "packages:psycopg2")
                && row
                    .evidence_files
                    .iter()
                    .any(|file| file.ends_with("requirements.txt"))
        }),
        "expected psycopg2 evidence from psycopg2-binary, got {:?}",
        inventory.rows
    );
}
