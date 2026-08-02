use super::*;
use bonsai_lang_api::{AdapterArc, LanguageRegistry};
use std::path::{Path, PathBuf};
use std::sync::Arc;

fn python_registry() -> Arc<LanguageRegistry> {
    let registry = Arc::new(LanguageRegistry::new());
    let adapter: AdapterArc = Arc::new(bonsai_lang_python::PythonAdapter::new());
    registry.register(adapter);
    registry
}

fn assert_function_was_parsed(workspace: &Workspace, expected: &str) {
    let files = workspace.vfs().all_files();
    assert_eq!(files.len(), 1, "the supported source file must be ingested");
    workspace
        .db()
        .decl_index(files[0])
        .expect("the ingested source must parse and lower");
    assert!(
        workspace.lookup_function(expected).is_some(),
        "expected parsed declaration {expected}"
    );
}

#[test]
fn exact_body_replay_reuses_resident_linkage_without_rebuilding_headers() {
    let root = tempfile::tempdir().expect("workspace tempdir");
    std::fs::write(
        root.path().join("app.py"),
        "def endpoint(value):\n    return value\n",
    )
    .expect("write Python fixture");
    let workspace = Workspace::open(root.path(), python_registry()).expect("open workspace");
    let linkage = workspace.compiler_linkage_index();
    let symbol = linkage
        .all_files()
        .flat_map(|file| linkage.decls_in(file))
        .find(|decl| decl.name == "endpoint")
        .map(|decl| decl.symbol)
        .expect("endpoint symbol");

    workspace.release_compiler_header_cache();
    assert!(workspace.inner.compiler_headers.read().is_none());
    assert_eq!(
        workspace
            .exact_decl(symbol)
            .expect("replay exact declaration")
            .name,
        "endpoint"
    );
    assert!(
        workspace.inner.compiler_headers.read().is_none(),
        "resident linkage must remain the exact-body identity source"
    );
}

#[test]
fn long_minified_named_source_is_parsed_by_single_file_and_parallel_ingest() {
    let root = tempfile::tempdir().expect("workspace tempdir");
    let path = root.path().join("app.min.py");
    let long_literal = format!("needle_{}", "x".repeat(6_000));
    let source = format!("def long_line():\n    return \"{long_literal}\"\n");
    std::fs::write(&path, &source).expect("write long source line");
    assert!(
        source.lines().any(|line| line.len() > 5_000),
        "fixture must exercise a source line beyond the former ingest limit"
    );

    let single = Workspace::open_query_matching_path(root.path(), python_registry(), Path::new("app.min.py"))
        .expect("single-file ingest must accept supported source regardless of name or line length");
    assert_function_was_parsed(&single, "long_line");

    let parallel = Workspace::open_query_matching_literal(root.path(), python_registry(), "needle_")
        .expect("parallel literal ingest must accept the same supported source");
    assert_function_was_parsed(&parallel, "long_line");
}

#[test]
fn multi_literal_candidate_open_ingests_the_union_only() {
    let root = tempfile::tempdir().expect("workspace tempdir");
    std::fs::write(
        root.path().join("source.py"),
        "def first_endpoint():\n    return 1\n",
    )
    .expect("write source endpoint");
    std::fs::write(
        root.path().join("target.py"),
        "def second_endpoint():\n    return 2\n",
    )
    .expect("write target endpoint");
    std::fs::write(
        root.path().join("unrelated.py"),
        "def unrelated():\n    return 3\n",
    )
    .expect("write unrelated source");

    let workspace = Workspace::open_query_matching_any_literal_with_options_and_events(
        root.path(),
        python_registry(),
        &["first_endpoint", "second_endpoint"],
        WorkspaceOpenOptions::parse_only(),
        &|_| {},
    )
    .expect("multi-literal candidate open");

    assert_eq!(workspace.stats().files, 2);
    assert!(workspace.lookup_function("first_endpoint").is_some());
    assert!(workspace.lookup_function("second_endpoint").is_some());
    assert!(workspace.lookup_function("unrelated").is_none());
}

#[test]
fn exact_query_worklist_preserves_global_file_identity_without_opening_siblings() {
    let root = tempfile::tempdir().expect("workspace tempdir");
    let alpha = root.path().join("alpha.py");
    let beta = root.path().join("beta.py");
    let alpha_text = "def alpha():\n    return 1\n";
    let beta_text = "def beta():\n    return 2\n";
    std::fs::write(&alpha, alpha_text).expect("write alpha");
    std::fs::write(&beta, beta_text).expect("write beta");
    let alpha = alpha.canonicalize().expect("canonical alpha");
    let beta = beta.canonicalize().expect("canonical beta");
    let source_inputs = vec![
        (
            0,
            alpha.to_string_lossy().into_owned(),
            bonsai_hash::fnv1a_bytes64(alpha_text.as_bytes()),
        ),
        (
            1,
            beta.to_string_lossy().into_owned(),
            bonsai_hash::fnv1a_bytes64(beta_text.as_bytes()),
        ),
    ];

    let workspace = Workspace::open_query_exact_files_with_source_inputs_and_events(
        root.path(),
        python_registry(),
        &[(FileId::new(1), beta.clone())],
        source_inputs,
        WorkspaceOpenOptions::parse_only(),
        &|_| {},
    )
    .expect("exact candidate open");

    assert_eq!(workspace.stats().files, 1);
    assert!(workspace.lookup_function("alpha").is_none());
    assert!(workspace.lookup_function("beta").is_some());
    assert_eq!(
        workspace
            .vfs()
            .path(FileId::new(1))
            .expect("global beta id")
            .as_path(),
        beta.as_path()
    );
}

#[test]
fn single_file_local_id_maps_to_its_persisted_header_partition() {
    let root = tempfile::tempdir().expect("workspace tempdir");
    std::fs::write(root.path().join("alpha.py"), "def alpha():\n    return 1\n").expect("write alpha");
    std::fs::write(root.path().join("beta.py"), "def beta():\n    return 2\n").expect("write beta");

    let complete = Workspace::index(root.path(), python_registry()).expect("complete workspace");
    complete
        .save_compiler_linkage_sidecar(root.path())
        .expect("persist linkage sidecar");
    let scoped = Workspace::open_query_matching_path(root.path(), python_registry(), Path::new("beta.py"))
        .expect("single-file query");
    assert_eq!(
        scoped.vfs().all_files(),
        vec![FileId::new(0)],
        "a navigation-only open stays dense and does not walk sibling metadata"
    );

    let headers = scoped.compiler_header_index_for_files(&scoped.vfs().all_files());
    assert_eq!(headers.all_files().collect::<Vec<_>>(), vec![FileId::new(1)]);
    assert!(headers.find_by_name("alpha").is_empty());
    assert_eq!(headers.find_by_name("beta").len(), 1);
}

#[test]
fn single_file_query_resolves_a_unique_workspace_path_filter() {
    let root = tempfile::tempdir().expect("workspace tempdir");
    std::fs::create_dir_all(root.path().join("src")).expect("create source dir");
    std::fs::write(
        root.path().join("src/executor.py"),
        "def execute():\n    return 1\n",
    )
    .expect("write nested source");

    let scoped =
        Workspace::open_query_matching_path(root.path(), python_registry(), Path::new("executor.py"))
            .expect("resolve unique nested basename");
    let paths = scoped
        .vfs()
        .all_files()
        .into_iter()
        .map(|file| scoped.vfs().path(file).expect("VFS path").as_ref().clone())
        .collect::<Vec<_>>();
    assert_eq!(
        paths,
        vec![root
            .path()
            .join("src/executor.py")
            .canonicalize()
            .expect("canonical fixture path")]
    );
}

#[test]
fn single_file_query_rejects_an_ambiguous_workspace_path_filter() {
    let root = tempfile::tempdir().expect("workspace tempdir");
    std::fs::create_dir_all(root.path().join("one")).expect("create first dir");
    std::fs::create_dir_all(root.path().join("two")).expect("create second dir");
    std::fs::write(root.path().join("one/executor.py"), "def one():\n    return 1\n")
        .expect("write first source");
    std::fs::write(root.path().join("two/executor.py"), "def two():\n    return 2\n")
        .expect("write second source");

    let error = Workspace::open_query_matching_path(root.path(), python_registry(), Path::new("executor.py"))
        .expect_err("ambiguous basename must fail closed");
    let rendered = error.to_string();
    assert!(rendered.contains("ambiguous"), "{rendered}");
    assert!(rendered.contains("one/executor.py"), "{rendered}");
    assert!(rendered.contains("two/executor.py"), "{rendered}");
}

#[test]
fn streaming_ingest_parses_delimiter_text_in_strings_and_comments() {
    let root = tempfile::tempdir().expect("workspace tempdir");
    let string_delimiters = "(".repeat(2_100);
    let comment_delimiters = format!("{}{}", "[".repeat(2_100), "{".repeat(2_100));
    let source = format!(
        "def delimiter_text():\n    payload = \"{string_delimiters}\"\n    # {comment_delimiters}\n    return payload\n"
    );
    std::fs::write(root.path().join("nested.py"), source).expect("write delimiter source");

    let workspace =
        Workspace::open_with_options(root.path(), python_registry(), WorkspaceOpenOptions::parse_only())
            .expect("streaming ingest must leave delimiter interpretation to tree-sitter");
    assert_function_was_parsed(&workspace, "delimiter_text");
}

#[test]
fn sidecar_validation_open_ingests_without_parsing() {
    let root = tempfile::tempdir().expect("workspace tempdir");
    std::fs::write(root.path().join("app.py"), "def main():\n    return 1\n").expect("write source");

    let workspace = Workspace::open_with_options(
        root.path(),
        python_registry(),
        WorkspaceOpenOptions::sidecar_validation_only(),
    )
    .expect("validation-only open");

    assert_eq!(workspace.stats().files, 1);
    let _ = workspace.db().complete_field_place_languages();
    assert_eq!(
        workspace.stats().cached_decl_indexes,
        0,
        "freshness and adapter-capability probes must not lower or retain syntax IR"
    );
}

#[test]
fn metadata_context_discovers_sources_without_ingesting_or_parsing_them() {
    let root = tempfile::tempdir().expect("workspace tempdir");
    std::fs::create_dir(root.path().join("src")).expect("source dir");
    std::fs::write(root.path().join("src/app.py"), "def main():\n    return 1\n").expect("write source");
    std::fs::write(root.path().join("pyproject.toml"), "[project]\nname='fixture'\n")
        .expect("write manifest");

    let workspace = Workspace::new(python_registry());
    let context = workspace
        .semantic_context_for_root(root.path())
        .expect("metadata context");

    assert_eq!(context.summary.indexed_files, 1);
    assert_eq!(context.summary.toolchain_manifests, 1);
    assert_eq!(workspace.stats().files, 0);
    assert_eq!(workspace.stats().reparsed_files, 0);
    assert_eq!(workspace.stats().cached_decl_indexes, 0);
}

#[test]
fn invalid_utf8_supported_source_is_a_visible_open_error() {
    let root = tempfile::tempdir().expect("workspace tempdir");
    std::fs::write(root.path().join("invalid.py"), [0xff, 0xfe, b'\n']).expect("write invalid UTF-8 fixture");

    let result =
        Workspace::open_with_options(root.path(), python_registry(), WorkspaceOpenOptions::parse_only());
    let error = match result {
        Ok(_) => panic!("a supported source file must never disappear from analysis silently"),
        Err(error) => error,
    };
    assert!(
        matches!(error, WorkspaceError::Io(ref io) if io.kind() == std::io::ErrorKind::InvalidData),
        "expected visible invalid-data failure, got {error:?}"
    );
}

#[test]
fn root_relative_source_filters_ignore_generated_ancestors_outside_workspace() {
    let root = PathBuf::from("/tmp/repo/target/smoke-workspace");
    let include_filters = Vec::new();
    let exclude_filters = vec!["target/".to_string()];
    let filter = PathFilterSpec {
        include_filters: &include_filters,
        exclude_filters: &exclude_filters,
    };
    assert!(
        source_path_allowed(&root, &root.join("app.py"), filter),
        "path filters must not exclude the selected workspace because an ancestor is named target"
    );
    assert!(
        !source_path_allowed(&root, &root.join("target/generated.py"), filter),
        "path filters must still exclude matching generated paths inside the selected workspace"
    );
}

#[test]
fn root_relative_source_filters_still_accept_explicit_absolute_paths() {
    let root = PathBuf::from("/tmp/repo/target/smoke-workspace");
    let include_filters = vec![root.join("app.py").to_string_lossy().into_owned()];
    let exclude_filters = Vec::new();
    let filter = PathFilterSpec {
        include_filters: &include_filters,
        exclude_filters: &exclude_filters,
    };
    assert!(source_path_allowed(&root, &root.join("app.py"), filter));
}

#[test]
fn root_anchored_filters_do_not_match_java_package_namespaces() {
    let root = PathBuf::from("/tmp/repo");
    let include_filters = Vec::new();
    let exclude_filters = vec!["^example/".to_string()];
    let filter = PathFilterSpec {
        include_filters: &include_filters,
        exclude_filters: &exclude_filters,
    };

    assert!(
        !source_path_allowed(&root, &root.join("example/App.java"), filter),
        "a root-level example project must remain excludable"
    );
    assert!(
        source_path_allowed(&root, &root.join("src/main/java/com/example/App.java"), filter),
        "a Java package component named `example` is production namespace syntax, not an example project"
    );
}
