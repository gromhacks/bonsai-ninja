//! Loader smoke tests — valid/invalid rulepack trees on disk.

use bonsai_security::{
    load_rulepack, load_workspace_local_rules,
    rule::{MatchKind, NonTaintEvaluation},
    rulepack_semantic_files, FlowClass, LoadError,
};
use std::fs;

fn write(path: &std::path::Path, content: &str) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, content).unwrap();
}

#[test]
fn loads_a_valid_python_pack() {
    let tmp = tempdir();
    let base = tmp.path().join("langs/python");
    write(
        &base.join("sources/flask.yml"),
        r"- id: python.flask.request_args
  enabled: true
  trust: remote
  tag: http-input
  match:
    kind: read
    target:
      attribute: [flask, request, args]
  description: Flask request.args.",
    );
    write(
        &base.join("sinks/cmdi.yml"),
        r"- id: python.cmdi.os_system
  enabled: true
  tag: command-injection
  severity: critical
  match:
    kind: call
    callee:
      attribute: [os, system]
  description: os.system.",
    );
    let pack = load_rulepack(tmp.path()).expect("loads");
    let py = pack.packs.get("python").expect("python pack");
    assert_eq!(py.sources.len(), 1);
    assert_eq!(py.sinks.len(), 1);
    assert_eq!(py.sources[0].match_spec.kind, MatchKind::Read);
    assert_eq!(py.sinks[0].match_spec.kind, MatchKind::Call);
}

#[test]
fn semantic_inventory_matches_loader_and_ignores_package_scaffolding() {
    let tmp = tempdir();
    write(&tmp.path().join("VERSION"), "test-pack\n");
    write(&tmp.path().join("metadata.yml"), "profiles: {}\n");
    write(&tmp.path().join("metadata.yaml"), "ignored: true\n");
    write(&tmp.path().join("Cargo.toml"), "[package]\nname = \"fixture\"\n");
    write(&tmp.path().join("build.rs"), "fn main() {}\n");
    write(
        &tmp.path().join("src/lib.rs"),
        "pub const SCAFFOLD: bool = true;\n",
    );
    write(&tmp.path().join("README.md"), "not rule semantics\n");
    write(&tmp.path().join("langs/x/sinks/x.yml"), "[]\n");
    write(&tmp.path().join("langs/x/sinks/ignored.txt"), "ignored\n");
    write(&tmp.path().join("sources/flat.yaml"), "[]\n");

    let files = rulepack_semantic_files(tmp.path()).expect("semantic inventory");
    let mut relative = files
        .iter()
        .map(|path| {
            path.strip_prefix(tmp.path())
                .expect("inventory path below root")
                .to_string_lossy()
                .replace('\\', "/")
        })
        .collect::<Vec<_>>();
    relative.sort();
    assert_eq!(
        relative,
        [
            "VERSION",
            "langs/x/sinks/x.yml",
            "metadata.yml",
            "sources/flat.yaml"
        ]
    );
}

#[test]
fn metadata_injects_profiles_test_paths_and_language_package_semantics() {
    let tmp = tempdir();
    write(
        &tmp.path().join("metadata.yml"),
        r#"profiles:
  production:
    trust: remote
    severity: high
    context: 16k
    exclude_tests: true
    exclude_paths: [tests/]
test_path_patterns: [/tests/, _test.unit]
languages:
  x:
    package_matching:
      strip_import_prefixes: ["runtime:"]
      strip_import_suffixes: [".header"]
      package_separators: ["::"]
      call_qualifier_from_package_tail:
        package_separator: "/"
        call_separators: ["."]
"#,
    );
    write(
        &tmp.path().join("langs/x/sinks/x.yml"),
        r"- id: x.test.sink
  enabled: true
  tag: test
  match:
    kind: call
    callee: {name: sink}
  description: metadata fixture",
    );

    let pack = load_rulepack(tmp.path()).expect("metadata-backed pack loads");
    let profile = pack
        .metadata
        .profiles
        .get("production")
        .expect("production profile");
    assert_eq!(profile.trust.map(|value| value.as_str()), Some("remote"));
    assert_eq!(profile.severity.map(|value| value.as_str()), Some("high"));
    assert_eq!(profile.exclude_tests, Some(true));
    assert_eq!(profile.exclude_paths, ["tests/"]);
    assert_eq!(pack.metadata.test_path_patterns, ["/tests/", "_test.unit"]);

    let semantics = &pack.packs["x"].sinks[0].package_matching;
    assert_eq!(semantics.strip_import_prefixes, ["runtime:"]);
    assert_eq!(semantics.strip_import_suffixes, [".header"]);
    assert_eq!(semantics.package_separators, ["::"]);
    let tail = semantics
        .call_qualifier_from_package_tail
        .as_ref()
        .expect("tail binding");
    assert_eq!(tail.package_separator, "/");
    assert_eq!(tail.call_separators, ["."]);
}

#[test]
fn metadata_injects_sink_tag_and_category_evaluation_policy() {
    let tmp = tempdir();
    write(
        &tmp.path().join("metadata.yml"),
        r#"sink_tag_semantics:
  transition:
    allow_file_package_evidence: true
    skip_call_package_gate: true
sink_category_semantics:
  local-pattern:
    non_taint_evaluation: pattern
  transition-audit:
    non_taint_evaluation: lifecycle
"#,
    );
    write(
        &tmp.path().join("langs/x/sinks/x.yml"),
        r"- id: x.test.pattern
  enabled: true
  tag: transition
  category: local-pattern
  match: {kind: call, callee: {name: sink}}
  description: metadata pattern fixture
- id: x.test.lifecycle
  enabled: true
  category: transition-audit
  match: {kind: call, callee: {name: release}}
  description: metadata lifecycle fixture",
    );

    let pack = load_rulepack(tmp.path()).expect("semantic metadata loads");
    let pattern = pack.find_rule_by_id("x.test.pattern").expect("pattern rule");
    let pattern_semantics = pattern.analysis_semantics.as_ref().expect("pattern semantics");
    assert_eq!(pattern_semantics.allow_file_package_evidence, Some(true));
    assert_eq!(pattern_semantics.skip_call_package_gate, Some(true));
    assert_eq!(
        pattern_semantics.non_taint_evaluation,
        Some(NonTaintEvaluation::Pattern)
    );

    let lifecycle = pack.find_rule_by_id("x.test.lifecycle").expect("lifecycle rule");
    assert_eq!(
        lifecycle
            .analysis_semantics
            .as_ref()
            .and_then(|semantics| semantics.non_taint_evaluation),
        Some(NonTaintEvaluation::Lifecycle)
    );
}

#[test]
fn loader_allows_unconstrained_sink_rules() {
    let tmp = tempdir();
    let base = tmp.path().join("langs/x");
    write(
        &base.join("sinks/xss.yml"),
        r"- id: x.xss.print
  enabled: true
  tag: xss
  match:
    kind: call
    callee:
      name: print
  description: bare print",
    );
    let pack = load_rulepack(tmp.path()).expect("sink constraints are not required");
    assert_eq!(pack.packs["x"].sinks.len(), 1);
}

#[test]
fn loader_rejects_duplicate_ids_across_languages() {
    // Two distinct language buckets share an `id`. The
    // workspace-flat `by_id` lookup (loader.rs::find_rule_by_id)
    // would silently last-write-wins without this validation.
    let tmp = tempdir();
    let dup = r"- id: shared.cmdi.dup
  enabled: true
  tag: command-injection
  match:
    kind: call
    callee:
      name: system
  description: ";
    write(&tmp.path().join("langs/x/sinks/a.yml"), dup);
    write(&tmp.path().join("langs/y/sinks/a.yml"), dup);
    let err = load_rulepack(tmp.path()).unwrap_err();
    assert!(matches!(err, LoadError::DuplicateId { .. }), "got {err:?}");
}

#[test]
fn loader_rejects_duplicate_ids_within_a_language() {
    let tmp = tempdir();
    let base = tmp.path().join("langs/x");
    let dup = r"- id: x.cmdi.dup
  enabled: true
  tag: command-injection
  match:
    kind: call
    callee:
      name: system
  description: ";
    write(&base.join("sinks/a.yml"), dup);
    write(&base.join("sinks/b.yml"), dup);
    let err = load_rulepack(tmp.path()).unwrap_err();
    assert!(matches!(err, LoadError::DuplicateId { .. }), "got {err:?}");
}

#[test]
fn loader_rejects_unknown_rule_fields() {
    let tmp = tempdir();
    let base = tmp.path().join("langs/python");
    write(
        &base.join("sinks/cmdi.yml"),
        r"- id: python.cmdi.os_system
  enabled: true
  language: python
  tag: command-injection
  severity: critical
  unexpected_field: nope
  match:
    kind: call
    callee:
      attribute: [os, system]
  description: os.system sink.",
    );
    let err = load_rulepack(tmp.path()).unwrap_err();
    assert!(matches!(err, LoadError::Parse { .. }), "got {err:?}");
    assert!(
        err.to_string().contains("unknown field"),
        "schema drift should fail with an unknown-field parse error, got {err}"
    );
}

#[test]
fn loader_rejects_callback_typing_fields_outside_typing_rules() {
    let tmp = tempdir();
    write(
        &tmp.path().join("langs/java/sources/remote.yml"),
        r"- id: java.source.invalid_callback_type
  enabled: true
  trust: remote
  tag: http-input
  callback_arg_index: 0
  callback_param_types: [[Request]]
  match:
    kind: call
    callee: {name: route}
  description: invalid source-owned callback signature",
    );

    let err = load_rulepack(tmp.path()).unwrap_err();
    assert!(
        matches!(err, LoadError::InvalidTypingDeclaration { .. }),
        "got {err:?}"
    );
}

#[test]
fn loader_rejects_type_match_without_callback_signature() {
    let tmp = tempdir();
    write(
        &tmp.path().join("langs/java/typing/callback.yml"),
        r"- id: java.typing.invalid_callable
  enabled: true
  returns_type: Wrong
  match:
    kind: type
    target: {name: Handler}
  description: invalid callable type without parameter signature",
    );

    let err = load_rulepack(tmp.path()).unwrap_err();
    assert!(
        matches!(err, LoadError::InvalidTypingDeclaration { .. }),
        "got {err:?}"
    );
}

#[test]
fn loader_accepts_missing_langs_dir_gracefully() {
    let tmp = tempdir();
    let pack = load_rulepack(tmp.path()).expect("empty rulepack root is ok");
    assert!(pack.packs.is_empty());
}

#[test]
fn loader_rejects_missing_root() {
    let err = load_rulepack(std::path::Path::new("/nonexistent-9df3ab")).unwrap_err();
    assert!(matches!(err, LoadError::MissingRoot(_)));
}

#[test]
fn workspace_local_returns_none_when_dir_absent() {
    let tmp = tempdir();
    let result = load_workspace_local_rules(tmp.path()).expect("ok when missing");
    assert!(result.is_none());
}

#[test]
fn workspace_local_loads_and_overrides_global_pack() {
    let tmp = tempdir();
    // Global pack — one Python sink.
    let global = tmp.path().join("rules-global");
    write(
        &global.join("langs/python/sinks/cmdi.yml"),
        r"- id: python.cmdi.os_system
  enabled: true
  tag: command-injection
  severity: critical
  match:
    kind: call
    callee:
      attribute: [os, system]
  description: os.system (global).",
    );
    // Workspace overlay — replaces the same id with a tweaked
    // description, plus adds a new sanitizer rule.
    let workspace = tmp.path().join("ws");
    write(
        &workspace.join(".bonsai/rules/python/sinks/cmdi.yml"),
        r"- id: python.cmdi.os_system
  enabled: true
  tag: command-injection
  severity: critical
  match:
    kind: call
    callee:
      attribute: [os, system]
  description: os.system (project override).",
    );
    write(
        &workspace.join(".bonsai/rules/python/sanitizers/local.yml"),
        r"- id: python.local.requires_admin
  enabled: true
  tag: csrf-protect
  match:
    kind: call
    callee:
      name: requires_admin
  description: project-local @requires_admin guard.",
    );

    let mut pack = load_rulepack(&global).expect("global loads");
    let local = load_workspace_local_rules(&workspace)
        .expect("local ok")
        .expect("local present");
    let overridden = pack.merge_overriding(local);
    assert_eq!(overridden, vec!["python.cmdi.os_system"]);

    let py = pack.packs.get("python").expect("python pack");
    let sink = py
        .sinks
        .iter()
        .find(|r| r.id == "python.cmdi.os_system")
        .expect("override present");
    assert!(sink.description.contains("project override"));
    assert!(py
        .sanitizers
        .iter()
        .any(|r| r.id == "python.local.requires_admin"));
}

#[test]
fn workspace_metadata_overlay_preserves_unspecified_bundled_fields() {
    let tmp = tempdir();
    let global = tmp.path().join("rules-global");
    write(
        &global.join("metadata.yml"),
        r"canonical_sink_families: [path]
sanitizer_credits:
  path-sanitize: [path-traversal]
sink_tag_semantics:
  path-traversal:
    suppress_inferred_sources: true
sanitizer_tag_semantics:
  path-sanitize:
    sanitizer_guard:
      use_receiver: true
languages:
  python:
    dependency_manifest_patterns: [pyproject.toml]
    normalize_hyphen_to_underscore: true
    package_aliases:
      bundled-dist: [bundled_import]
",
    );
    write(
        &global.join("langs/python/sanitizers/path.yml"),
        r"- id: python.path.realpath
  enabled: true
  tag: path-sanitize
  match:
    kind: call
    callee: {name: realpath}
  description: global path sanitizer.",
    );
    write(
        &global.join("langs/python/sinks/path.yml"),
        r"- id: python.path.open
  enabled: true
  tag: path-traversal
  severity: high
  match:
    kind: call
    callee: {name: open}
  description: global path sink.",
    );

    let workspace = tmp.path().join("ws");
    write(
        &workspace.join(".bonsai/rules/metadata.yml"),
        r"sanitizer_credits:
  local-clean: [path-traversal]
sink_tag_semantics:
  path-traversal:
    suppress_local_source_flow_classes: [environment-input]
languages:
  python:
    package_aliases:
      local-dist: [local_import]
",
    );

    let mut pack = load_rulepack(&global).expect("global loads");
    let local = load_workspace_local_rules(&workspace)
        .expect("local metadata loads")
        .expect("local pack present");
    pack.merge_overriding(local);

    let python = pack.metadata.languages.get("python").expect("Python metadata");
    assert_eq!(python.dependency_manifest_patterns, ["pyproject.toml"]);
    assert!(python.normalize_hyphen_to_underscore);
    assert_eq!(
        python.package_aliases.get("bundled-dist").unwrap(),
        &["bundled_import"]
    );
    assert_eq!(
        python.package_aliases.get("local-dist").unwrap(),
        &["local_import"]
    );
    assert_eq!(
        pack.metadata.sanitizer_credits.get("path-sanitize").unwrap(),
        &["path-traversal"]
    );
    assert_eq!(
        pack.metadata.sanitizer_credits.get("local-clean").unwrap(),
        &["path-traversal"]
    );
    let python_pack = pack.packs.get("python").expect("Python pack");
    assert_eq!(
        python_pack.sinks[0]
            .analysis_semantics
            .as_ref()
            .and_then(|semantics| semantics.suppress_inferred_sources),
        Some(true)
    );
    assert_eq!(
        python_pack.sinks[0]
            .analysis_semantics
            .as_ref()
            .map(|semantics| semantics.suppress_local_source_flow_classes.as_slice()),
        Some([FlowClass::EnvironmentInput].as_slice())
    );
    assert!(python_pack.sanitizers[0]
        .analysis_semantics
        .as_ref()
        .and_then(|semantics| semantics.sanitizer_guard.as_ref())
        .is_some_and(|guard| guard.use_receiver));
}

#[test]
fn yaml_declared_language_matches_directory_layout() {
    // langs/<lang>/ wrapper supplies the language, AND the YAML
    // also names the same language. The drift guard should accept
    // this because they agree.
    let tmp = tempdir();
    write(
        &tmp.path().join("langs/python/sinks/cmdi.yml"),
        r"- id: python.cmdi.os_system
  enabled: true
  language: python
  tag: command-injection
  severity: critical
  match:
    kind: call
    callee:
      attribute: [os, system]
  description: os.system.",
    );
    let pack = load_rulepack(tmp.path()).expect("loads");
    let py = pack.packs.get("python").expect("python pack");
    assert_eq!(py.sinks.len(), 1);
    assert_eq!(py.sinks[0].language, "python");
}

#[test]
fn yaml_language_mismatched_with_directory_is_rejected() {
    let tmp = tempdir();
    write(
        &tmp.path().join("langs/python/sinks/cmdi.yml"),
        r"- id: python.cmdi.os_system
  enabled: true
  language: ruby
  tag: command-injection
  severity: critical
  match:
    kind: call
    callee:
      attribute: [os, system]
  description: ",
    );
    let err = load_rulepack(tmp.path()).unwrap_err();
    assert!(matches!(err, LoadError::LanguageMismatch { .. }), "got {err:?}");
}

#[test]
fn flat_layout_with_yaml_language_loads() {
    // No `langs/` wrapper — rules live directly under
    // `<root>/{sources,sinks,sanitizers}/` and YAML declares
    // `language:`. This is the layout custom rulepack projects use.
    let tmp = tempdir();
    write(
        &tmp.path().join("sinks/cmdi.yml"),
        r"- id: custom.cmdi.os_system
  enabled: true
  language: python
  tag: command-injection
  severity: critical
  match:
    kind: call
    callee:
      attribute: [os, system]
  description: os.system (custom pack).",
    );
    write(
        &tmp.path().join("sources/flask.yml"),
        r"- id: custom.flask.request_args
  enabled: true
  language: python
  trust: remote
  tag: http-input
  match:
    kind: read
    target:
      attribute: [flask, request, args]
  description: Flask request.args.",
    );
    let pack = load_rulepack(tmp.path()).expect("flat loads");
    let py = pack.packs.get("python").expect("python pack");
    assert_eq!(py.sources.len(), 1);
    assert_eq!(py.sinks.len(), 1);
    assert_eq!(py.sources[0].language, "python");
    assert_eq!(py.sinks[0].language, "python");
}

#[test]
fn flat_layout_rule_without_yaml_language_is_rejected() {
    let tmp = tempdir();
    write(
        &tmp.path().join("sinks/cmdi.yml"),
        r"- id: custom.cmdi.os_system
  enabled: true
  tag: command-injection
  severity: critical
  match:
    kind: call
    callee:
      attribute: [os, system]
  description: ",
    );
    let err = load_rulepack(tmp.path()).unwrap_err();
    assert!(matches!(err, LoadError::MissingLanguage { .. }), "got {err:?}");
}

#[test]
fn flat_and_per_lang_layouts_coexist_in_one_root() {
    // A pack that mixes both layouts: a python source in the
    // canonical `langs/python/sources/` location AND a python sink
    // in the flat `sinks/` directory. Both end up in the same
    // language pack.
    let tmp = tempdir();
    write(
        &tmp.path().join("langs/python/sources/flask.yml"),
        r"- id: python.flask.request_args
  enabled: true
  trust: remote
  tag: http-input
  match:
    kind: read
    target:
      attribute: [flask, request, args]
  description: Flask request.args.",
    );
    write(
        &tmp.path().join("sinks/cmdi.yml"),
        r"- id: custom.cmdi.os_system
  enabled: true
  language: python
  tag: command-injection
  severity: critical
  match:
    kind: call
    callee:
      attribute: [os, system]
  description: os.system.",
    );
    let pack = load_rulepack(tmp.path()).expect("mixed layout loads");
    let py = pack.packs.get("python").expect("python pack");
    assert_eq!(py.sources.len(), 1, "per-lang source loaded");
    assert_eq!(py.sinks.len(), 1, "flat sink routed into python");
    assert_eq!(py.sources[0].id, "python.flask.request_args");
    assert_eq!(py.sinks[0].id, "custom.cmdi.os_system");
}

#[test]
fn flat_layout_routes_rules_to_their_declared_language() {
    // One flat sinks/ file, two rules for two different languages.
    let tmp = tempdir();
    write(
        &tmp.path().join("sinks/multi.yml"),
        r"- id: pylib.cmdi.os_system
  enabled: true
  language: python
  tag: command-injection
  severity: critical
  match:
    kind: call
    callee:
      attribute: [os, system]
  description: ' '
- id: rblib.cmdi.system
  enabled: true
  language: ruby
  tag: command-injection
  severity: critical
  match:
    kind: call
    callee:
      name: system
    target:
  constraints:
    - namespace: Kernel
  description: ' '",
    );
    let pack = load_rulepack(tmp.path()).expect("flat loads");
    assert!(pack.packs.contains_key("python"));
    assert!(pack.packs.contains_key("ruby"));
    assert_eq!(pack.packs["python"].sinks.len(), 1);
    assert_eq!(pack.packs["ruby"].sinks.len(), 1);
}

fn tempdir() -> TempDir {
    TempDir::new()
}

struct TempDir {
    path: std::path::PathBuf,
}

impl TempDir {
    fn new() -> Self {
        let base = std::env::temp_dir();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        for attempt in 0..100 {
            let path = base.join(format!(
                "bonsai-security-test-{}-{nanos}-{attempt}",
                std::process::id()
            ));
            match std::fs::create_dir(&path) {
                Ok(()) => return Self { path },
                Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(err) => panic!("create temp dir {}: {err}", path.display()),
            }
        }
        panic!("create unique temp dir under {}", base.display());
    }
    fn path(&self) -> &std::path::Path {
        &self.path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}
