//! End-to-end integration tests for the public workspace API.

use bonsai_lang_api::LanguageRegistry;
use bonsai_lang_rust::RustAdapter;
use bonsai_workspace::{Workspace, WorkspaceError, WorkspaceOpenOptions};
use std::sync::Arc;

fn make_ws() -> Workspace {
    let registry = Arc::new(LanguageRegistry::new());
    registry.register(Arc::new(RustAdapter::new()));
    Workspace::new(registry)
}

#[test]
fn ingest_and_trace_roundtrip() {
    let ws = make_ws();
    ws.vfs().write(
        "/virtual/a.rs",
        Arc::<str>::from("fn main() { helper(); }\nfn helper() {}"),
    );
    let func = ws.lookup_function("main").expect("main present");
    let trace = ws.db().trace_function(func, Default::default());
    assert!(!trace.steps.is_empty(), "trace should emit steps");
    assert!(trace
        .steps
        .iter()
        .any(|s| matches!(s.kind, bonsai_trace::TraceStepKind::EnterFunction)));
}

#[test]
fn trace_rejects_ambiguous_entry_symbol() {
    let ws = make_ws();
    ws.vfs().write("/virtual/a.rs", Arc::<str>::from("fn dup() {}"));
    ws.vfs().write("/virtual/b.rs", Arc::<str>::from("fn dup() {}"));

    let err = ws.trace_from("dup").expect_err("ambiguous entry should fail");
    match err {
        WorkspaceError::AmbiguousSymbol {
            count, candidates, ..
        } => {
            assert_eq!(count, 2);
            assert_eq!(candidates.len(), 2);
        }
        other => panic!("expected AmbiguousSymbol, got {other:?}"),
    }
}

#[test]
fn trace_accepts_file_qualified_ambiguous_entry_symbol() {
    let ws = make_ws();
    ws.vfs().write(
        "/virtual/a.rs",
        Arc::<str>::from("fn dup() { a_only(); }\nfn a_only() {}"),
    );
    ws.vfs().write(
        "/virtual/b.rs",
        Arc::<str>::from("fn dup() { b_only(); }\nfn b_only() {}"),
    );

    let trace = ws
        .trace_from("/virtual/a.rs:1:dup")
        .expect("file-qualified duplicate entry should resolve exactly");
    assert!(
        trace.steps.iter().any(|step| step.function == "a_only"),
        "trace should follow the a.rs duplicate, not the b.rs duplicate"
    );
    assert!(
        !trace.steps.iter().any(|step| step.function == "b_only"),
        "file-qualified trace must not over-fan into the other duplicate"
    );
}

#[test]
fn edit_invalidates_only_touched_file() {
    let ws = make_ws();
    ws.vfs().write("/virtual/a.rs", Arc::<str>::from("fn a() {}"));
    ws.vfs().write("/virtual/b.rs", Arc::<str>::from("fn b() {}"));
    let _ = ws.lookup_function("a").unwrap();
    let _ = ws.lookup_function("b").unwrap();
    let before = ws.stats();

    // Apply an edit to file "a" via the public API.
    let id = ws.apply_edit(std::path::Path::new("/virtual/a.rs"), "fn a() { 42; }".into());
    let _ = ws.db().decl_index(id).unwrap();
    let after = ws.stats();

    // We re-parsed at least one file (the edited one). b must still be findable without new work.
    assert!(after.reparsed_files > before.reparsed_files);
    assert!(ws.lookup_function("b").is_some());
}

#[test]
fn edit_invalidates_flow_id_cache() {
    let ws = make_ws();
    let path = std::path::Path::new("/virtual/a.rs");
    ws.vfs()
        .write(path, Arc::<str>::from("fn entry() { sink(); }\nfn sink() {}\n"));
    let sink_before = ws.lookup_function("sink").expect("sink before edit");
    let labels_before = ws
        .flow_ids()
        .labels_for_func(sink_before, ws.db(), ws.vfs())
        .to_vec();
    assert!(!labels_before.is_empty(), "expected initial flow id labels");

    ws.apply_edit(path, "fn entry() {}\nfn sink() {}\n".into());
    let sink_after = ws.lookup_function("sink").expect("sink after edit");
    let labels_after = ws
        .flow_ids()
        .labels_for_func(sink_after, ws.db(), ws.vfs())
        .to_vec();

    assert!(
        !labels_after.is_empty(),
        "expected recomputed flow id labels after edit"
    );
    assert_ne!(
        labels_before, labels_after,
        "flow id labels should be recomputed after an edit changes the caller chain"
    );
    assert_eq!(
        labels_after,
        vec![bonsai_workspace::flow_ids::compute_flow_id(&[String::from(
            "sink"
        )])],
        "the stale entry -> sink call edge must not survive edit invalidation"
    );
}

#[test]
fn edit_invalidates_cached_resolved_call_graph() {
    let ws = make_ws();
    let path = std::path::Path::new("/virtual/a.rs");
    ws.vfs()
        .write(path, Arc::<str>::from("fn entry() { sink(); }\nfn sink() {}\n"));
    let before = ws.cached_resolved_call_graph();

    ws.apply_edit(path, "fn entry() {}\nfn sink() {}\n".into());
    let after = ws.cached_resolved_call_graph();

    assert!(
        !Arc::ptr_eq(&before, &after),
        "file edits must drop the cached resolved call graph"
    );
}

#[test]
fn multi_file_workspace_decl_roundtrip() {
    let ws = make_ws();
    for (path, text) in [
        ("/w/m.rs", "fn main() {}"),
        ("/w/util.rs", "pub fn util() {}"),
        ("/w/api.rs", "pub struct Api; impl Api { pub fn call(&self) {} }"),
    ] {
        ws.vfs().write(path, Arc::<str>::from(text));
    }
    let global = ws.db().global_index();
    let names: Vec<String> = global
        .all_files()
        .flat_map(|f| {
            global
                .decls_in(f)
                .iter()
                .map(|d| d.name.clone())
                .collect::<Vec<_>>()
        })
        .collect();
    assert!(names.contains(&"main".to_string()));
    assert!(names.contains(&"util".to_string()));
    assert!(names.contains(&"Api".to_string()));
    assert!(names.contains(&"call".to_string()));
}

#[test]
fn ingest_dir_respects_bonsaiignore() {
    let unique = format!(
        "bonsai-ignore-test-{}-{:?}",
        std::process::id(),
        std::time::SystemTime::now()
    );
    let root = std::env::temp_dir().join(unique);
    std::fs::create_dir_all(root.join("ignored_dir")).expect("create temp workspace");
    std::fs::write(root.join(".bonsaiignore"), "ignored.rs\nignored_dir/\n").expect("write ignore file");
    std::fs::write(root.join("kept.rs"), "fn kept() {}\n").expect("write kept file");
    std::fs::write(root.join("ignored.rs"), "fn ignored_file() {}\n").expect("write ignored file");
    std::fs::write(
        root.join("ignored_dir").join("nested.rs"),
        "fn ignored_nested() {}\n",
    )
    .expect("write ignored nested file");

    let registry = Arc::new(LanguageRegistry::new());
    registry.register(Arc::new(RustAdapter::new()));
    let ws = Workspace::open_with_options(&root, registry, WorkspaceOpenOptions::parse_only())
        .expect("open temp workspace");
    let indexed_paths = ws
        .vfs()
        .all_files()
        .into_iter()
        .map(|file| ws.vfs().path(file).expect("indexed path").display().to_string())
        .collect::<Vec<_>>();

    assert!(
        indexed_paths.iter().any(|path| path.ends_with("kept.rs")),
        "kept.rs should be indexed: {indexed_paths:?}"
    );
    assert!(
        indexed_paths
            .iter()
            .all(|path| !path.ends_with("ignored.rs") && !path.contains("ignored_dir")),
        ".bonsaiignore should suppress ignored files: {indexed_paths:?}"
    );

    std::fs::remove_dir_all(root).expect("remove temp workspace");
}
