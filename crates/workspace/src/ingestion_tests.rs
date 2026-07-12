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
