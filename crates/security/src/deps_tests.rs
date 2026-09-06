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
        },
        analysis_semantics: None,
        taint_semantics: None,
        lifecycle_transition: None,
        returns_type: None,
        callback_param_types: Vec::new(),
        callback_arg_index: None,
        callback_field_path: Vec::new(),
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

#[test]
fn every_bundled_manifest_pattern_participates_in_root_cache_freshness() {
    for (language, metadata) in bundled_metadata().languages {
        for pattern in metadata.dependency_manifest_patterns {
            let filename = pattern.replace('*', "sample");
            assert!(
                bonsai_common::dependency_metadata::is_dependency_metadata_file(&filename),
                "{language}: {pattern} cannot be omitted from root-only cache fingerprints"
            );
        }
    }
}

#[test]
fn dependency_package_evidence_ignores_manifest_prose_and_comments() {
    let cases = [
        ("package.json", "javascript", r#"{"name":"sample","description":"express","dependencies":{"fastify":"*"}}"#, "express", "fastify"),
        ("Cargo.toml", "rust", "[package]\nname = 'sample'\nversion = '0.1.0'\ndescription = 'reqwest'\n# reqwest = '*'\n[dependencies]\nserde = '1'\n", "reqwest", "serde"),
        ("pom.xml", "java", "<project><!-- <artifactId>log4j-core</artifactId> --><description>log4j-core</description><dependencies><dependency><artifactId>jackson-databind</artifactId></dependency></dependencies></project>", "log4j-core", "jackson-databind"),
        ("pubspec.yaml", "dart", "name: sample\ndescription: dio\n# dio: any\ndependencies:\n  http: any\n", "dio", "http"),
    ];
    for (filename, language, text, absent, present) in cases {
        let root = tempfile::tempdir().expect("manifest fixture");
        std::fs::write(root.path().join(filename), text).expect("write manifest");
        let context = build_workspace_dependency_package_context(root.path(), &bundled_metadata(), None);
        let packages = workspace_dependency_packages_from_context(&context, language).packages;
        assert!(
            !packages.contains(absent),
            "{filename} prose/comment is not package evidence: {packages:?}"
        );
        assert!(
            packages.contains(present),
            "{filename} lost a declared dependency: {packages:?}"
        );
    }
}

#[test]
fn structured_manifests_preserve_declared_aliases_nested_locks_and_short_names() {
    let metadata = bundled_metadata();
    for (file, language, source, expected) in [
        ("package.json", "javascript", r#"{"dependencies":{"q":"1","alias":"npm:@scope/real@^1"}}"#, vec!["q", "alias", "@scope/real"]),
        ("package-lock.json", "javascript", r#"{"dependencies":{"outer":{"dependencies":{"inner":{}}}},"packages":{"node_modules/@scope/pkg":{},"node_modules/a/node_modules/b":{}}}"#, vec!["outer", "inner", "@scope/pkg", "b"]),
        ("Cargo.toml", "rust", "[target.'cfg(unix)'.dev-dependencies]\nalias = { package = 'real-crate', version = '1' }\n[workspace.dependencies]\nshared = '1'\n", vec!["alias", "real-crate", "shared"]),
        ("pyproject.toml", "python", "[project.optional-dependencies]\ntest = ['requests[socks]>=2']\n[dependency-groups]\nlint = ['ruff==0.1']\n", vec!["requests", "ruff"]),
        ("app.csproj", "csharp", "<Project><!-- <PackageReference Include='fake'/> --><ItemGroup><PackageReference Include='Real.Package'/></ItemGroup></Project>", vec!["Real.Package"]),
        ("requirements.txt", "python", "# express requests\nrequests[socks]>=2; python_version > '3' # comment\nq==1\n", vec!["requests", "q"]),
    ] {
        let packages = dependency_manifest_packages(Path::new(file), source, language, &metadata, None).expect(file);
        for package in expected { assert!(packages.contains(package), "{file}: {package} missing: {packages:?}"); }
        assert!(!packages.contains("fake") && !packages.contains("express"));
    }
}

#[test]
fn invalid_or_unmodeled_manifests_never_fall_back_to_raw_package_names() {
    let metadata = bundled_metadata();
    for (file, language, source) in [
        ("package.json", "javascript", r#"{"dependencies":{"express":"1"}, broken"#),
        ("plugin.gemspec", "ruby", "# actionpack\n"),
        ("pom.xml", "java", "<!DOCTYPE a [<!ENTITY x SYSTEM 'file:///private'>]><project><artifactId>&x;</artifactId></project>"),
    ] {
        assert!(dependency_manifest_packages(Path::new(file), source, language, &metadata, None).is_err(), "{file}");
    }
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("pyproject.toml"), "[project\n# django").unwrap();
    let ws = Workspace::new(bonsai_adapters::all_languages_registry());
    let mut pack = pack_with_bundled_metadata();
    pack.packs.insert(
        "python".into(),
        LanguagePack {
            language: "python".into(),
            sources: Vec::new(),
            sinks: vec![python_package_rule("django")],
            sanitizers: Vec::new(),
            typing: Vec::new(),
        },
    );
    let inventory = build_inventory(&pack, &ws, root.path());
    assert!(inventory.rows.is_empty());
    assert!(!inventory.analysis_complete);
    assert!(inventory
        .analysis_incomplete_reasons
        .iter()
        .any(|reason| reason.contains("pyproject.toml")));
    let report =
        crate::deps_analysis::dependency_analysis(&ws, &pack, root.path(), Default::default()).unwrap();
    assert!(
        !report.analysis_complete,
        "empty dependency report must retain manifest errors"
    );
}

#[test]
fn code_manifests_require_compiler_proven_calls_and_static_values() {
    let ws = Workspace::new(bonsai_adapters::all_languages_registry());
    let metadata = bundled_metadata();
    for (file, language, source, present, absent) in [
        ("Gemfile", "ruby", "# gem 'fake'\nnotes = \"gem 'fake'\"\ngem 'actionpack'\n", vec!["actionpack"], vec!["fake"]),
        ("Gemfile", "ruby", "def gem(name)\n puts name\nend\ngem 'actionpack'\n", vec![], vec!["actionpack"]),
        ("setup.py", "python", "from setuptools import setup\nsetup(name='app', description='fake', install_requires=['requests>=2'])\n", vec!["app", "requests"], vec!["fake"]),
    ] {
        let packages = dependency_manifest_packages(Path::new(file), source, language, &metadata, Some(&ws)).expect(file);
        for package in present { assert!(packages.contains(package), "{file}: {package} missing: {packages:?}"); }
        for package in absent { assert!(!packages.contains(package), "{file}: false package {package}: {packages:?}"); }
    }
    assert!(dependency_manifest_packages(
        Path::new("Gemfile"),
        "gem ENV['PACKAGE']\n",
        "ruby",
        &metadata,
        Some(&ws)
    )
    .is_err());
    assert!(dependency_manifest_packages(
        Path::new("Gemfile"),
        "def unused\n gem 'actionpack'\nend\n",
        "ruby",
        &metadata,
        Some(&ws)
    )
    .is_err());
}

#[test]
fn code_manifest_imports_do_not_erase_workspace_local_provider_shadowing() {
    let metadata = bundled_metadata();
    let ws = Workspace::new(bonsai_adapters::all_languages_registry());
    for (provider, source) in [
        (
            "setuptools.py",
            "from setuptools import setup\nsetup(install_requires=['django'])\n",
        ),
        (
            "setuptools.py",
            "import setuptools as packaging\npackaging.setup(install_requires=['django'])\n",
        ),
        (
            "setuptools/__init__.py",
            "from setuptools import setup\nsetup(install_requires=['django'])\n",
        ),
    ] {
        let root = tempfile::tempdir().unwrap();
        let provider = root.path().join(provider);
        std::fs::create_dir_all(provider.parent().unwrap()).unwrap();
        std::fs::write(&provider, "def setup(**options):\n    return None\n").unwrap();
        let error = dependency_manifest_packages(
            &root.path().join("setup.py"),
            source,
            "python",
            &metadata,
            Some(&ws),
        )
        .expect_err("local or unselected providers must not become external dependency evidence");
        assert!(error.to_string().contains("workspace-local"), "{error}");
    }

    let root = tempfile::tempdir().unwrap();
    std::fs::write(
        root.path().join("setup.py"),
        "from setuptools import setup\nsetup(install_requires=['django'])\n",
    )
    .unwrap();
    let ws = Workspace::index(root.path(), bonsai_adapters::all_languages_registry()).unwrap();
    let before = build_workspace_dependency_package_context(root.path(), &metadata, Some(&ws));
    assert!(before.incomplete_reasons.is_empty());
    // Deliberately leave the new provider outside the selected VFS: scope
    // exclusions must not turn a local import into an external package.
    std::fs::write(
        root.path().join("setuptools.py"),
        "def setup(**options):\n    return None\n",
    )
    .unwrap();
    let after = build_workspace_dependency_package_context(root.path(), &metadata, Some(&ws));
    assert_ne!(before.fingerprint, after.fingerprint);
    assert!(after
        .incomplete_reasons
        .iter()
        .any(|reason| reason.contains("workspace-local")));
}

#[test]
fn dependency_layouts_are_validated_and_part_of_snapshot_identity() {
    let root = tempfile::tempdir().unwrap();
    let mut metadata = bundled_metadata();
    let before = build_workspace_dependency_package_context(root.path(), &metadata, None).fingerprint;
    let javascript = metadata.languages.get_mut("javascript").unwrap();
    javascript.dependency_manifest_layouts[0].packages[0].path = vec!["alternate".into()];
    let after = build_workspace_dependency_package_context(root.path(), &metadata, None).fingerprint;
    assert_ne!(before, after);
    for source in [
        r#"{"files":["x"],"format":"json","packages":[{"path":[],"capture":"no-group"}]}"#,
        r#"{"files":["x"],"format":"xml","packages":[{"path":[],"keys":true}]}"#,
        r#"{"files":["x"],"format":"lines","packages":[{"path":[],"capture":"(unanchored)"}]}"#,
        r#"{"files":["x"],"format":"code","adapter":"ruby","calls":[{"callee":{"name":"gem"},"arguments":[{"index":0,"keyword":"name"}]}]}"#,
    ] {
        let layout: crate::loader::DependencyManifestLayout = serde_json::from_str(source).unwrap();
        assert!(layout.validate().is_err(), "{source}");
    }
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
    rule.manifests.push("pom.xml".to_string());
    rule.lockfiles.push("Cargo.lock".to_string());
    std::fs::write(root.join("Cargo.lock"), "version = 3\n").expect("unrelated lockfile");

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
    let row = inventory.rows.iter().find(|row| row.key == "log4j-core").unwrap();
    assert!(row.signals.iter().any(|signal| signal == "manifests:pom.xml"));
    assert!(row.signals.iter().all(|signal| signal != "lockfiles:Cargo.lock"));
    assert_eq!(row.evidence_files, ["pom.xml"]);
    std::fs::remove_dir_all(root).expect("fixture cleanup");
}

#[test]
fn a_manifest_filename_without_package_evidence_never_establishes_a_dependency() {
    let root = temp_root("bonsai-deps-unrelated-manifest");
    std::fs::write(
        root.join("pyproject.toml"),
        "[project]\ndependencies = [\"Flask>=3\"]\n",
    )
    .expect("manifest");
    let ws = Workspace::new(std::sync::Arc::new(bonsai_lang_api::LanguageRegistry::new()));
    let mut rule = python_package_rule("django");
    rule.packages.push("pyramid".to_string());
    rule.manifests.push("pyproject.toml".to_string());
    let mut pack = pack_with_bundled_metadata();
    pack.packs.insert(
        "python".to_string(),
        LanguagePack {
            language: "python".to_string(),
            sources: Vec::new(),
            sinks: vec![rule],
            sanitizers: Vec::new(),
            typing: Vec::new(),
        },
    );
    let inventory = build_inventory(&pack, &ws, &root);
    assert!(
        inventory.rows.is_empty(),
        "unrelated packages: {:?}",
        inventory.rows
    );
    std::fs::remove_dir_all(root).expect("fixture cleanup");
}

#[test]
fn workspace_dependency_packages_alias_python_distribution_names_to_imports() {
    let root = temp_root("bonsai-deps-python-aliases");
    std::fs::write(
        root.join("requirements.txt"),
        "psycopg2-binary==2.9.9\ndjangorestframework==3.15.1\nmysql-connector-python==9.1.0\n",
    )
    .expect("requirements");

    let context = build_workspace_dependency_package_context(&root, &bundled_metadata(), None);
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

    let context = build_workspace_dependency_package_context(&root, &bundled_metadata(), None);
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
    let initial_context = build_workspace_dependency_package_context(&root, &metadata, None);
    let initial = workspace_dependency_packages_from_context(&initial_context, "python");
    assert!(initial.packages.contains("psycopg2"));
    assert!(!initial.packages.contains("requests"));

    std::fs::write(&manifest, "requests==2.32.3\n").expect("updated requirements");
    let refreshed_context = build_workspace_dependency_package_context(&root, &metadata, None);
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
    let snapshot = super::begin_workspace_dependency_package_snapshot(&root, workspace_id, &pack, None);

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
    let _refreshed_snapshot =
        super::begin_workspace_dependency_package_snapshot(&root, workspace_id, &pack, None);
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
