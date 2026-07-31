use super::{
    best_textual_relevance_key, file_path_matches_filter, make_callable_name_filter, textual_relevance_key,
};
use bonsai_workspace::Workspace;
use std::sync::Arc;

#[test]
fn textual_relevance_orders_exact_prefix_and_substring() {
    let exact = textual_relevance_key("token", Some("token"), false);
    let case_exact = textual_relevance_key("Token", Some("token"), false);
    let prefix = textual_relevance_key("token_value", Some("token"), false);
    let substring = textual_relevance_key("user_token_value", Some("token"), false);
    let miss = textual_relevance_key("session", Some("token"), false);

    assert!(exact < case_exact);
    assert!(case_exact < prefix);
    assert!(prefix < substring);
    assert!(substring < miss);
}

#[test]
fn textual_relevance_preserves_deterministic_sort_for_regex_or_empty_query() {
    assert_eq!(
        textual_relevance_key("token", Some("tok.*"), true),
        (u8::MAX, "token".len())
    );
    assert_eq!(
        textual_relevance_key("token", None, false),
        (u8::MAX, "token".len())
    );
}

#[test]
fn best_textual_relevance_uses_best_candidate_in_row() {
    let key = best_textual_relevance_key(["user", "request.token", "session"], Some("token"), false);
    assert_eq!(key, textual_relevance_key("request.token", Some("token"), false));
}

#[test]
fn callable_filter_accepts_compiler_qualified_name_for_source_spelling() {
    let filter = make_callable_name_filter(Some("pkg.Service.execute"), false).expect("callable filter");
    assert!(filter("client.execute"));
    assert!(filter("pkg.Service.execute"));
    assert!(!filter("client.run"));

    let regex =
        make_callable_name_filter(Some("^pkg\\.Service\\.execute$"), true).expect("regex callable filter");
    assert!(regex("pkg.Service.execute"));
    assert!(
        !regex("client.execute"),
        "an explicit regex must not be rewritten to its lexical tail"
    );
}

#[test]
fn file_path_filters_are_workspace_relative() {
    let root = tempfile::tempdir().expect("tempdir");
    let workspace_root = root.path().join("tests/chosen-workspace");
    std::fs::create_dir_all(workspace_root.join("tests")).expect("create workspace");
    let registry = Arc::new(bonsai_lang_api::LanguageRegistry::default());
    let ws = Workspace::open_with_options(
        &workspace_root,
        registry,
        bonsai_workspace::WorkspaceOpenOptions::parse_only(),
    )
    .expect("open empty workspace");

    assert!(!file_path_matches_filter(
        &ws,
        &workspace_root.join("app.py").to_string_lossy(),
        "tests/"
    ));
    assert!(file_path_matches_filter(
        &ws,
        &workspace_root.join("tests/helper.py").to_string_lossy(),
        "tests/"
    ));
    assert!(file_path_matches_filter(
        &ws,
        &workspace_root.join("app.py").to_string_lossy(),
        &workspace_root.join("app.py").to_string_lossy()
    ));
}

#[test]
fn directory_file_filters_match_path_components() {
    let root = tempfile::tempdir().expect("tempdir");
    let workspace_root = root.path().join("chosen-workspace");
    std::fs::create_dir_all(workspace_root.join("tests")).expect("create workspace");
    let registry = Arc::new(bonsai_lang_api::LanguageRegistry::default());
    let ws = Workspace::open_with_options(
        &workspace_root,
        registry,
        bonsai_workspace::WorkspaceOpenOptions::parse_only(),
    )
    .expect("open empty workspace");

    assert!(file_path_matches_filter(
        &ws,
        &workspace_root.join("tests/helper.py").to_string_lossy(),
        "tests/"
    ));
    assert!(!file_path_matches_filter(
        &ws,
        &workspace_root.join("latest/helper.py").to_string_lossy(),
        "test/"
    ));
    assert!(!file_path_matches_filter(
        &ws,
        &workspace_root.join("unit-tests/helper.py").to_string_lossy(),
        "tests/"
    ));
    assert!(file_path_matches_filter(
        &ws,
        &workspace_root.join("src/test/helper.py").to_string_lossy(),
        "src/test/"
    ));
}
