//! SDK-level workspace open/index behavior.
//!
//! The CLI is only one front-end. SDK users need the same
//! "index once, query many" cache strategy without reaching into
//! CLI-only helpers, so these tests pin the public workspace API.

use bonsai_lang_api::{AdapterArc, LanguageRegistry};
use bonsai_workspace::{
    dataflow::DataFlowCache, idg_sidecar_enabled_for_file_count, idg_sidecar_path,
    value_flow::ValueFlowCache, Workspace, WorkspaceOpenOptions,
};
use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

static IDG_SIDECAR_LIMIT_ENV_LOCK: Mutex<()> = Mutex::new(());

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
fn sdk_index_is_structural_by_default() {
    let root = tempdir_for_test("bonsai-sdk-index");
    write_fixture(&root);

    let ws = Workspace::index(&root, python_registry()).expect("index workspace");
    assert!(
        !ws.dataflow().is_prewarmed(),
        "index should stay structural unless full prewarm is requested"
    );
    assert_eq!(
        ws.dataflow().len(),
        0,
        "structural index should not eagerly compute dataflow facts"
    );
    let sidecar = DataFlowCache::factstore_sidecar_path(&root);
    assert!(
        !sidecar.exists(),
        "structural index should not persist a dataflow sidecar"
    );

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn workspace_root_under_generated_ancestor_still_indexes_root_sources() {
    let outer = tempdir_for_test("bonsai-root-under-generated-ancestor");
    let root = outer.join("target").join("chosen-workspace");
    std::fs::create_dir_all(root.join("target")).expect("create nested target fixture");
    std::fs::write(root.join(".bonsaiignore"), "target/\n").expect("write explicit generated-path policy");
    std::fs::write(root.join("app.py"), "def handle():\n    return 1\n").expect("write root source");
    std::fs::write(
        root.join("target").join("generated.py"),
        "def generated():\n    return 2\n",
    )
    .expect("write nested generated source");

    let ws = Workspace::index(&root, python_registry()).expect("index workspace under target ancestor");
    assert_eq!(
        ws.stats().files,
        1,
        "the selected workspace root must be honored even when an ancestor is named target"
    );
    let indexed_paths = ws
        .vfs()
        .all_files()
        .into_iter()
        .filter_map(|file| {
            ws.vfs()
                .path(file)
                .ok()
                .map(|path| path.to_string_lossy().into_owned())
        })
        .collect::<Vec<_>>();
    assert!(
        indexed_paths.iter().any(|path| path.ends_with("app.py")),
        "root source should be indexed: {indexed_paths:#?}"
    );
    assert!(
        indexed_paths.iter().all(|path| !path.ends_with("generated.py")),
        "generated subdirectory inside the workspace should still be skipped: {indexed_paths:#?}"
    );

    let fingerprints = ws
        .source_file_fingerprints(&root)
        .expect("fingerprint workspace under target ancestor");
    assert_eq!(
        fingerprints.len(),
        1,
        "fingerprinting must use the same root-relative generated-path policy"
    );
    assert_eq!(
        fingerprints[0].hash,
        bonsai_hash::fnv1a_bytes64(b"def handle():\n    return 1\n"),
        "streaming fingerprints must preserve the canonical content digest"
    );

    let _ = std::fs::remove_dir_all(outer);
}

#[test]
fn sdk_full_prewarm_writes_dataflow_sidecar() {
    let root = tempdir_for_test("bonsai-sdk-full-prewarm");
    write_fixture(&root);

    let ws = Workspace::index_full_prewarm(&root, python_registry()).expect("full prewarm workspace");
    assert!(
        ws.dataflow().is_prewarmed(),
        "explicit full prewarm should compute reusable taint facts"
    );
    assert!(ws.dataflow().len() >= 2);
    let sidecar = DataFlowCache::factstore_sidecar_path(&root);
    assert!(
        sidecar.exists(),
        "explicit full prewarm should persist the reusable dataflow sidecar"
    );
    assert!(
        ws.value_flow().is_empty(),
        "full prewarm should leave the legacy per-function ValueFlowGraph projection on demand"
    );
    assert!(
        !ValueFlowCache::sidecar_path(&root).exists(),
        "full prewarm should not persist an all-function compatibility projection"
    );
    assert!(
        ws.db().idg_service().is_some(),
        "full prewarm must retain the canonical workspace IDG"
    );

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn sdk_full_prewarm_persists_global_idg_without_a_file_count_ceiling() {
    let _guard = IDG_SIDECAR_LIMIT_ENV_LOCK.lock().expect("idg sidecar env lock");
    let old_limit = std::env::var("BONSAI_IDG_SIDECAR_FILE_LIMIT").ok();
    std::env::set_var("BONSAI_IDG_SIDECAR_FILE_LIMIT", "0");

    assert!(idg_sidecar_enabled_for_file_count(5_001));
    assert!(idg_sidecar_enabled_for_file_count(usize::MAX));

    let root = tempdir_for_test("bonsai-sdk-full-prewarm-unbounded-idg-sidecar");
    write_fixture(&root);

    let ws = Workspace::open_with_options(&root, python_registry(), WorkspaceOpenOptions::full_prewarm())
        .expect("full prewarm workspace with unbounded IDG persistence");
    assert!(
        ws.dataflow().is_prewarmed(),
        "full prewarm should still compute reusable dataflow facts"
    );
    assert!(
        ws.db().idg_service().is_some(),
        "full prewarm must retain the workspace-global IDG at every scale"
    );
    assert!(
        idg_sidecar_path(&root).exists(),
        "legacy file-limit configuration must not disable streamed IDG persistence"
    );

    match old_limit {
        Some(value) => std::env::set_var("BONSAI_IDG_SIDECAR_FILE_LIMIT", value),
        None => std::env::remove_var("BONSAI_IDG_SIDECAR_FILE_LIMIT"),
    }
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn sdk_query_open_loads_sidecar_without_full_prewarm() {
    let root = tempdir_for_test("bonsai-sdk-query-open");
    write_fixture(&root);

    Workspace::index_full_prewarm(&root, python_registry()).expect("full prewarm workspace");
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

    Workspace::index_full_prewarm(&root, python_registry()).expect("full prewarm workspace");
    let ws = Workspace::open_with_options(&root, python_registry(), WorkspaceOpenOptions::parse_only())
        .expect("open parse-only workspace");
    assert_eq!(
        ws.dataflow().len(),
        0,
        "parse-only open should not load or prewarm dataflow"
    );

    let _ = std::fs::remove_dir_all(root);
}
