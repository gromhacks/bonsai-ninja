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

fn javascript_registry() -> Arc<LanguageRegistry> {
    let registry = Arc::new(LanguageRegistry::new());
    let adapter: AdapterArc = Arc::new(bonsai_lang_javascript::JavaScriptAdapter::new());
    registry.register(adapter);
    registry
}

fn c_registry() -> Arc<LanguageRegistry> {
    let registry = Arc::new(LanguageRegistry::new());
    let adapter: AdapterArc = Arc::new(bonsai_lang_c::CAdapter::new());
    registry.register(adapter);
    registry
}

#[test]
fn invalid_utf8_is_admitted_only_inside_grammar_proven_comments() {
    let root = tempfile::tempdir().expect("workspace tempdir");
    let comment_path = root.path().join("comment.c");
    let mut comment_source = b"/* legacy quote: x */\nint answer(void) { return 42; }\n".to_vec();
    let comment_byte = comment_source
        .iter()
        .position(|byte| *byte == b'x')
        .expect("comment marker byte");
    comment_source[comment_byte] = 0x92;
    std::fs::write(&comment_path, &comment_source).expect("write comment source");

    let workspace = Workspace::open(root.path(), c_registry())
        .expect("a legacy byte proven to be comment trivia must not discard valid code");
    assert!(workspace.lookup_function("answer").is_some());
    let comment_path = comment_path.canonicalize().expect("canonical comment source");
    let file = workspace
        .vfs()
        .lookup(&comment_path)
        .expect("comment source in VFS");
    let snapshot = workspace.vfs().snapshot(file).expect("comment source snapshot");
    assert_eq!(
        snapshot.text.len(),
        comment_source.len(),
        "byte spans must remain stable"
    );
    assert_eq!(snapshot.text.as_bytes()[comment_byte], b' ');

    let code_root = tempfile::tempdir().expect("workspace tempdir");
    let code_path = code_root.path().join("code.c");
    let mut code_source = b"int bad_name(void) { return 0; }\n".to_vec();
    code_source[5] = 0x92;
    std::fs::write(code_path, code_source).expect("write invalid code source");
    let error = Workspace::open(code_root.path(), c_registry())
        .expect_err("invalid executable syntax must fail closed");
    assert!(
        error.to_string().contains("outside a grammar-proven comment"),
        "unexpected error: {error}"
    );
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
fn minified_ecmascript_requires_explicit_compiler_input_opt_in() {
    let root = tempfile::tempdir().expect("workspace tempdir");
    std::fs::write(root.path().join("app.js"), "function maintained(){return 1;}\n")
        .expect("write maintained JavaScript");
    std::fs::write(
        root.path().join("vendor.min.js"),
        "function generatedBundle(){return 2;}\n",
    )
    .expect("write minified JavaScript");

    let default = Workspace::open_with_options(
        root.path(),
        javascript_registry(),
        WorkspaceOpenOptions::parse_only(),
    )
    .expect("open default production input profile");
    assert_eq!(default.stats().files, 1);
    assert!(default.lookup_function("maintained").is_some());
    assert!(default.lookup_function("generatedBundle").is_none());
    assert!(
        default
            .source_file_stamp(&root.path().join("vendor.min.js"))
            .expect("default source stamp")
            .is_none(),
        "watch/refresh discovery must use the same compiler-input profile"
    );
    assert!(
        default
            .refresh_file_from_disk(&root.path().join("vendor.min.js"))
            .is_err(),
        "direct refresh must not bypass the compiler-input profile"
    );
    assert_eq!(
        default
            .source_file_fingerprints(root.path())
            .expect("default fingerprints")
            .len(),
        1
    );

    let mut include = WorkspaceOpenOptions::parse_only();
    include.include_minified_sources = true;
    let complete = Workspace::open_with_options(root.path(), javascript_registry(), include)
        .expect("open minified-inclusive compiler profile");
    assert_eq!(complete.stats().files, 2);
    assert!(complete.lookup_function("maintained").is_some());
    assert!(complete.lookup_function("generatedBundle").is_some());
    assert!(complete
        .source_file_stamp(&root.path().join("vendor.min.js"))
        .expect("inclusive source stamp")
        .is_some());
    assert_eq!(
        complete
            .source_file_fingerprints(root.path())
            .expect("inclusive fingerprints")
            .len(),
        2
    );
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
        .save_compiler_object_sidecar(root.path())
        .expect("persist compiler objects");
    complete
        .save_compiler_linkage_sidecar(root.path())
        .expect("persist linkage sidecar");
    let scoped = Workspace::open_query_matching_path(root.path(), python_registry(), Path::new("beta.py"))
        .expect("single-file query");
    assert_eq!(
        scoped.vfs().all_files(),
        vec![FileId::new(1)],
        "a warmed file-local query must preserve the full workspace ordinal so it can decode the exact compiler object"
    );

    let headers = scoped.compiler_header_index_for_files(&scoped.vfs().all_files());
    assert_eq!(headers.all_files().collect::<Vec<_>>(), vec![FileId::new(1)]);
    assert!(headers.find_by_name("alpha").is_empty());
    assert_eq!(headers.find_by_name("beta").len(), 1);
}

#[test]
fn single_file_query_keeps_workspace_identity_without_compiler_objects() {
    let root = tempfile::tempdir().expect("workspace tempdir");
    std::fs::write(root.path().join("alpha.py"), "def alpha():\n    return 1\n").unwrap();
    std::fs::write(root.path().join("beta.py"), "def beta():\n    return 2\n").unwrap();
    let complete = Workspace::index(root.path(), python_registry()).unwrap();
    complete.save_compiler_linkage_sidecar(root.path()).unwrap();
    let scoped = Workspace::open_query_matching_path_with_options(
        root.path(),
        python_registry(),
        Path::new("beta.py"),
        WorkspaceOpenOptions {
            load_compiler_object_sidecar: false,
            ..WorkspaceOpenOptions::parse_only()
        },
    )
    .unwrap();
    let file = scoped.vfs().all_files()[0];
    let body = scoped.exact_decl_index_shared(file).expect("exact selected body");
    assert_eq!(
        file,
        FileId::new(1),
        "cold objects must not renumber a file with persisted headers"
    );
    assert!(body.defs.iter().any(|decl| decl.name == "beta"));
    assert!(body.defs.iter().all(|decl| decl.name != "alpha"));
    assert_eq!(scoped.stats().files, 1, "unselected bodies stay unopened");
}

#[test]
fn single_file_query_does_not_borrow_an_outdated_generation_ordinal() {
    let root = tempfile::tempdir().expect("workspace tempdir");
    std::fs::write(root.path().join("beta.py"), "def beta():\n    return 2\n").unwrap();
    let first = Workspace::index(root.path(), python_registry()).unwrap();
    first.save_compiler_object_sidecar(root.path()).unwrap();
    std::fs::write(root.path().join("alpha.py"), "def alpha():\n    return 1\n").unwrap();
    let scoped =
        Workspace::open_query_matching_path(root.path(), python_registry(), Path::new("beta.py")).unwrap();
    assert_eq!(
        scoped.vfs().all_files(),
        [FileId::new(1)],
        "source additions change the canonical ordinal even if beta's bytes did not change"
    );
    assert!(scoped
        .exact_decl_index_shared(FileId::new(1))
        .unwrap()
        .defs
        .iter()
        .any(|decl| decl.name == "beta"));
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

#[test]
fn lazy_source_table_interns_matching_files_by_identity_and_loads_on_first_use() {
    let root = tempfile::tempdir().expect("workspace tempdir");
    // The workspace interns canonical paths (`/private/var` on macOS).
    let root_dir = root.path().canonicalize().expect("canonical tempdir");
    let lazy_path = root_dir.join("lazy.py");
    let eager_path = root_dir.join("eager.py");
    std::fs::write(&lazy_path, "def lazy_fn():\n    return 1\n").expect("write lazy");
    std::fs::write(&eager_path, "def eager_fn():\n    return 2\n").expect("write eager");

    // The identities and stamps a cache manifest would record.
    let probe = Workspace::new_with_open_options(python_registry(), WorkspaceOpenOptions::lazy_query());
    let identities = probe.source_file_identities(root.path()).expect("identities");
    let stamps = probe.source_file_stamps(root.path()).expect("stamps");
    assert_eq!(identities.len(), 2);
    assert!(identities.iter().all(|identity| identity.text_exact));
    let mut table = LazySourceTable::default();
    for identity in &identities {
        let stamp = stamps
            .iter()
            .find(|stamp| stamp.path == identity.path)
            .expect("stamp for identity")
            .clone();
        let mut stamp = stamp;
        if identity.path.file_name().and_then(|name| name.to_str()) == Some("eager.py") {
            // A stale stamp must fall back to reading the file during ingest.
            stamp.len += 1;
        }
        table.insert(
            identity.path.clone(),
            LazySourceRecord {
                stamp,
                identity: SourceIdentity {
                    len: identity.len,
                    hash: identity.hash,
                    digest: identity.digest,
                },
            },
        );
    }

    let eager = Workspace::open(root.path(), python_registry()).expect("eager open");
    let lazy = Workspace::open_with_options_lazy_sources_and_events(
        root.path(),
        python_registry(),
        WorkspaceOpenOptions::lazy_query(),
        Some(&table),
        &|_| {},
    )
    .expect("lazy open");
    assert_eq!(
        lazy.vfs().lazy_source_counts(),
        (1, 0),
        "only the still-matching file is lazy"
    );
    // Identity-only surfaces agree with the eager open without a read.
    let mut eager_hashes = eager.complete_source_content_hashes().expect("eager hashes");
    let mut lazy_hashes = lazy.complete_source_content_hashes().expect("lazy hashes");
    eager_hashes.sort();
    lazy_hashes.sort();
    assert_eq!(eager_hashes, lazy_hashes);
    assert_eq!(lazy.vfs().lazy_source_counts(), (1, 0));
    let lazy_file = lazy.vfs().lookup(&lazy_path).expect("lazy file id");
    assert_eq!(
        lazy.vfs().text_len(lazy_file).expect("len"),
        "def lazy_fn():\n    return 1\n".len() as u64
    );
    assert!(
        lazy.db().adapter_for(lazy_file).is_some(),
        "adapter lookup needs only the path"
    );
    assert_eq!(lazy.vfs().lazy_source_counts(), (1, 0));

    // First semantic use loads and verifies the text.
    let index = lazy.db().decl_index(lazy_file).expect("decl index");
    assert!(index.defs.iter().any(|decl| decl.name == "lazy_fn"));
    assert_eq!(lazy.vfs().lazy_source_counts(), (1, 1));
    assert_eq!(
        lazy.vfs().snapshot(lazy_file).expect("snapshot").text.as_ref(),
        "def lazy_fn():\n    return 1\n"
    );
}

#[test]
fn lazy_source_whose_text_changed_after_validation_fails_loudly() {
    let root = tempfile::tempdir().expect("workspace tempdir");
    let path = root
        .path()
        .canonicalize()
        .expect("canonical tempdir")
        .join("a.py");
    std::fs::write(&path, "def before():\n    return 1\n").expect("write");
    let probe = Workspace::new_with_open_options(python_registry(), WorkspaceOpenOptions::lazy_query());
    let identity = probe
        .source_file_identities(root.path())
        .expect("identities")
        .remove(0);
    let stamp = probe.source_file_stamps(root.path()).expect("stamps").remove(0);
    let mut table = LazySourceTable::default();
    table.insert(
        path.clone(),
        LazySourceRecord {
            stamp,
            identity: SourceIdentity {
                len: identity.len,
                hash: identity.hash,
                digest: identity.digest,
            },
        },
    );
    let ws = Workspace::open_with_options_lazy_sources_and_events(
        root.path(),
        python_registry(),
        WorkspaceOpenOptions::lazy_query(),
        Some(&table),
        &|_| {},
    )
    .expect("lazy open");
    let file = ws.vfs().lookup(&path).expect("file");
    assert_eq!(ws.vfs().lazy_source_counts(), (1, 0));
    // Same length so the metadata stamp alone cannot tell; the loader's hash
    // check must.
    std::fs::write(&path, "def change():\n    return 1\n").expect("rewrite");
    let error = ws
        .vfs()
        .snapshot(file)
        .expect_err("changed text must not load silently");
    assert!(
        error
            .to_string()
            .contains("source changed after cache validation"),
        "{error}"
    );
}

#[test]
fn filtered_open_interns_scoped_sources_by_identity_and_validates_without_reads() {
    let root = tempfile::tempdir().expect("workspace tempdir");
    let root_dir = root.path().canonicalize().expect("canonical tempdir");
    std::fs::write(root_dir.join("lazy.py"), "def lazy_fn():\n    return 1\n").expect("write lazy");
    std::fs::write(root_dir.join("other.py"), "def other_fn():\n    return 2\n").expect("write other");
    let probe = Workspace::new_with_open_options(python_registry(), WorkspaceOpenOptions::lazy_query());
    let identities = probe.source_file_identities(root.path()).expect("identities");
    let stamps = probe.source_file_stamps(root.path()).expect("stamps");
    let mut table = LazySourceTable::default();
    for identity in &identities {
        let stamp = stamps
            .iter()
            .find(|stamp| stamp.path == identity.path)
            .expect("stamp")
            .clone();
        table.insert(
            identity.path.clone(),
            LazySourceRecord {
                stamp,
                identity: SourceIdentity {
                    len: identity.len,
                    hash: identity.hash,
                    digest: identity.digest,
                },
            },
        );
    }
    let eager = Workspace::open(root.path(), python_registry()).expect("eager open");
    let scoped = Workspace::open_query_filtered_paths_with_options_lazy_sources_and_events(
        root.path(),
        python_registry(),
        &["lazy.py".to_string()],
        &[],
        WorkspaceOpenOptions::lazy_query(),
        Some(&table),
        &|_| {},
    )
    .expect("scoped lazy open");
    assert_eq!(
        scoped.vfs().all_files().len(),
        1,
        "only the scoped file is interned"
    );
    assert_eq!(scoped.vfs().lazy_source_counts(), (1, 0));
    // The complete source table (both files) comes from the identities: the
    // hashes match an eager open, and nothing was read to produce them.
    let mut eager_hashes = eager.complete_source_content_hashes().expect("eager hashes");
    let mut scoped_hashes = scoped.complete_source_content_hashes().expect("scoped hashes");
    eager_hashes.sort();
    scoped_hashes.sort();
    assert_eq!(eager_hashes, scoped_hashes);
    assert_eq!(scoped.vfs().lazy_source_counts(), (1, 0));
    let file = scoped
        .vfs()
        .lookup(&root_dir.join("lazy.py"))
        .expect("scoped file id");
    let index = scoped.db().decl_index(file).expect("decl index");
    assert!(index.defs.iter().any(|decl| decl.name == "lazy_fn"));
    assert_eq!(scoped.vfs().lazy_source_counts(), (1, 1));
}
