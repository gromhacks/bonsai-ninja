//! SDK-level workspace open/index behavior.
//!
//! The CLI is only one front-end. SDK users need the same
//! "index once, query many" cache strategy without reaching into
//! CLI-only helpers, so these tests pin the public workspace API.

use bonsai_lang_api::{AdapterArc, LanguageRegistry};
use bonsai_workspace::{dataflow::DataFlowCache, Workspace, WorkspaceOpenOptions};
use std::{
    path::PathBuf,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

fn python_registry() -> Arc<LanguageRegistry> {
    let registry = Arc::new(LanguageRegistry::new());
    let adapter: AdapterArc = Arc::new(bonsai_lang_python::PythonAdapter::new());
    registry.register(adapter);
    registry
}

fn tempdir_for_test(name: &str) -> PathBuf {
    let base = std::env::temp_dir();
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_nanos();
    for attempt in 0..100 {
        let path = base.join(format!("{name}-{}-{nanos}-{attempt}", std::process::id()));
        match std::fs::create_dir(&path) {
            Ok(()) => return path,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => panic!("create tempdir {}: {e}", path.display()),
        }
    }
    panic!("could not allocate tempdir for {name}");
}

fn write_fixture(root: &std::path::Path) {
    std::fs::write(
        root.join("app.py"),
        "def handle(req):\n    sink(req)\ndef sink(value):\n    pass\n",
    )
    .expect("write fixture");
}

#[test]
fn sdk_index_writes_dataflow_sidecar() {
    let root = tempdir_for_test("bonsai-sdk-index");
    write_fixture(&root);

    let ws = Workspace::index(&root, python_registry()).expect("index workspace");
    assert!(
        ws.dataflow().is_prewarmed(),
        "index should eagerly prewarm reusable taint facts"
    );
    assert!(ws.dataflow().len() >= 2);
    let sidecar = DataFlowCache::factstore_sidecar_path(&root);
    assert!(
        sidecar.exists(),
        "index should persist the reusable dataflow sidecar"
    );

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn sdk_query_open_loads_sidecar_without_full_prewarm() {
    let root = tempdir_for_test("bonsai-sdk-query-open");
    write_fixture(&root);

    Workspace::index(&root, python_registry()).expect("index workspace");
    let ws = Workspace::open_query(&root, python_registry()).expect("open query workspace");
    assert!(
        ws.dataflow().len() >= 2,
        "query open should reuse indexed dataflow facts from sidecar"
    );
    assert!(
        !ws.dataflow().is_prewarmed(),
        "query open should not force a full eager prewarm"
    );

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn sdk_parse_only_skips_sidecar_load_and_prewarm() {
    let root = tempdir_for_test("bonsai-sdk-parse-only");
    write_fixture(&root);

    Workspace::index(&root, python_registry()).expect("index workspace");
    let ws = Workspace::open_with_options(&root, python_registry(), WorkspaceOpenOptions::parse_only())
        .expect("open parse-only workspace");
    assert_eq!(
        ws.dataflow().len(),
        0,
        "parse-only open should not load or prewarm dataflow"
    );

    let _ = std::fs::remove_dir_all(root);
}
