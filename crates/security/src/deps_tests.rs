use super::*;
use crate::loader::{load_rulepack, LanguagePack, Rulepack, RulepackMetadata};
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

fn bundled_metadata() -> RulepackMetadata {
    load_rulepack(
        &std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join("security-patterns"),
    )
    .expect("bundled rulepack")
    .metadata
}

fn pack_with_bundled_metadata() -> Rulepack {
    let mut pack = Rulepack::default();
    pack.metadata = bundled_metadata();
    pack
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
        package_matching: Default::default(),
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
fn manifest_recognition_reuses_the_language_mapping() {
    let metadata = bundled_metadata();
    for basename in [
        "Pipfile",
        "mix.exs",
        "go.work",
        "packages.config",
        "project.csproj",
        "plugin.gemspec",
        "Package.resolved",
    ] {
        assert!(
            is_dependency_manifest_basename(basename, &metadata),
            "{basename} has a language mapping and must be scanned"
        );
    }
    assert!(!is_dependency_manifest_basename("notes.yaml", &metadata));
}

#[cfg(unix)]
#[test]
fn manifest_scan_does_not_follow_directory_symlinks_outside_the_workspace() {
    let root = temp_root("bonsai-deps-symlink-root");
    let outside = temp_root("bonsai-deps-symlink-outside");
    std::fs::write(outside.join("Pipfile"), "requests = \"*\"").expect("outside manifest");
    std::os::unix::fs::symlink(&outside, root.join("linked")).expect("directory symlink");

    let paths = scan_manifest_files(&root, &pack_with_bundled_metadata());
    assert!(
        paths.is_empty(),
        "dependency inventory must not follow workspace symlinks: {paths:?}"
    );
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

    let mut pack = pack_with_bundled_metadata();
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

    let mut pack = pack_with_bundled_metadata();
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

    let context = build_workspace_dependency_package_context(&root, &bundled_metadata());
    let packages = workspace_dependency_packages_from_context(&context, "python").packages;
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

    let context = build_workspace_dependency_package_context(&root, &bundled_metadata());
    let packages = workspace_dependency_packages_from_context(&context, "rust").packages;
    assert!(
        packages.contains("percent_encoding"),
        "expected percent_encoding alias from percent-encoding, got {:?}",
        packages
    );
}

#[test]
fn broad_manifest_refresh_replaces_stale_package_context() {
    let root = temp_root("bonsai-deps-manifest-refresh");
    let manifest = root.join("requirements.txt");
    std::fs::write(&manifest, "psycopg2-binary==2.9.9\n").expect("initial requirements");

    let metadata = bundled_metadata();
    let initial_context = build_workspace_dependency_package_context(&root, &metadata);
    let initial = workspace_dependency_packages_from_context(&initial_context, "python");
    assert!(initial.packages.contains("psycopg2"));
    assert!(!initial.packages.contains("requests"));

    std::fs::write(&manifest, "requests==2.32.3\n").expect("updated requirements");
    let refreshed_context = build_workspace_dependency_package_context(&root, &metadata);
    let refreshed = workspace_dependency_packages_from_context(&refreshed_context, "python");
    assert_ne!(initial.fingerprint, refreshed.fingerprint);
    assert!(!refreshed.packages.contains("psycopg2"));
    assert!(refreshed.packages.contains("requests"));
}

#[test]
fn analysis_manifest_snapshot_remains_immutable_until_the_run_finishes() {
    let root = temp_root("bonsai-deps-analysis-snapshot");
    let manifest = root.join("requirements.txt");
    std::fs::write(&manifest, "psycopg2-binary==2.9.9\n").expect("initial requirements");
    let workspace_id = 9_001;
    let pack = pack_with_bundled_metadata();
    let snapshot = super::begin_workspace_dependency_package_snapshot(&root, workspace_id, &pack);

    let initial =
        super::workspace_dependency_packages_for_language_in_workspace(&root, "python", workspace_id);
    assert!(initial.packages.contains("psycopg2"));
    std::fs::write(&manifest, "requests==2.32.3\n").expect("updated requirements");

    let during_run =
        super::workspace_dependency_packages_for_language_in_workspace(&root, "python", workspace_id);
    assert_eq!(initial.fingerprint, during_run.fingerprint);
    assert!(during_run.packages.contains("psycopg2"));
    assert!(!during_run.packages.contains("requests"));

    drop(snapshot);
    let _refreshed_snapshot = super::begin_workspace_dependency_package_snapshot(&root, workspace_id, &pack);
    let after_run =
        super::workspace_dependency_packages_for_language_in_workspace(&root, "python", workspace_id);
    assert_ne!(after_run.fingerprint, initial.fingerprint);
    assert!(!after_run.packages.contains("psycopg2"));
    assert!(after_run.packages.contains("requests"));
}

#[test]
fn dependency_inventory_reports_python_distribution_alias_as_package_evidence() {
    let root = temp_root("bonsai-deps-python-inventory-alias");
    std::fs::write(root.join("requirements.txt"), "psycopg2-binary==2.9.9\n").expect("requirements");
    let ws = Workspace::new(std::sync::Arc::new(bonsai_lang_api::LanguageRegistry::new()));

    let mut pack = pack_with_bundled_metadata();
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
