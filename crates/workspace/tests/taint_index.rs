//! Workspace-wide taint graph index basic round-trip and
//! invalidation. Stage 6 of the eager-graph roadmap; stage 7's
//! sidecar save/load is exercised in `sidecar_round_trip_via_disk`
//! and `sidecar_with_mismatched_version_is_ignored` below.

use bonsai_common::FuncId;
use bonsai_lang_api::LanguageRegistry;
use bonsai_taint::EntryTaintGraph;
use bonsai_workspace::{
    taint_index::{cleanup_sidecar_temp_files, TaintGraphIndex},
    Workspace,
};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

fn tempdir_for(name: &str) -> PathBuf {
    let base = std::env::temp_dir();
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
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

fn ws_with_python_source(source: &str) -> Workspace {
    let registry = Arc::new(LanguageRegistry::new());
    registry.register(Arc::new(bonsai_lang_python::PythonAdapter::new()));
    let ws = Workspace::new(registry);
    ws.vfs().write("/w/app.py".to_string(), Arc::<str>::from(source));
    for file in ws.vfs().all_files() {
        let _ = ws.db().decl_index(file);
    }
    ws
}

#[test]
fn cache_returns_inserted_graph() {
    let idx = TaintGraphIndex::new();
    let func = FuncId::new(42);
    let seeds: Vec<String> = vec!["x".into(), "y".into()];
    let graph = Arc::new(EntryTaintGraph::default());
    let stored = idx.insert_if_absent(func, seeds.clone(), graph.clone());
    assert!(Arc::ptr_eq(&stored, &graph));

    let got = idx.get(func, &seeds).expect("entry present");
    assert!(Arc::ptr_eq(&got, &graph));
    assert_eq!(idx.len(), 1);
}

#[test]
fn double_insert_keeps_first_winner() {
    let idx = TaintGraphIndex::new();
    let func = FuncId::new(1);
    let seeds: Vec<String> = vec!["a".into()];
    let first = Arc::new(EntryTaintGraph::default());
    let second = Arc::new(EntryTaintGraph::default());
    let stored_first = idx.insert_if_absent(func, seeds.clone(), first.clone());
    let stored_second = idx.insert_if_absent(func, seeds.clone(), second.clone());
    assert!(
        Arc::ptr_eq(&stored_first, &stored_second),
        "two concurrent fills must collapse onto the first winner"
    );
    assert!(Arc::ptr_eq(&stored_first, &first));
    assert!(!Arc::ptr_eq(&stored_first, &second));
}

#[test]
fn sidecar_file_validator_rejects_corrupt_payload_even_when_size_matches() {
    let root = tempdir_for("taint-graph-corrupt-validator");
    let ws = ws_with_python_source("def entry(x):\n    return x\n");
    let path = TaintGraphIndex::sidecar_path(&root);
    let idx = TaintGraphIndex::new();
    idx.insert_if_absent(
        FuncId::new(1),
        vec!["x".to_string()],
        Arc::new(EntryTaintGraph::default()),
    );
    idx.save_to_disk(&path, ws.db())
        .expect("save taint graph sidecar");
    assert_eq!(
        TaintGraphIndex::validate_sidecar_file(&path).expect("validate fresh taint graph sidecar"),
        1
    );

    let bytes = std::fs::metadata(&path).expect("taint graph metadata").len();
    std::fs::write(&path, vec![0_u8; bytes as usize]).expect("overwrite same-size corrupt factstore");
    assert!(
        TaintGraphIndex::validate_sidecar_file(&path).is_err(),
        "same-size corrupt taint graph factstore must not validate"
    );

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn configured_sidecar_paths_do_not_collide() {
    let root = tempdir_for("taint-graph-config-paths");
    let legacy = TaintGraphIndex::sidecar_path(&root);
    let source = TaintGraphIndex::sidecar_path_for_config(&root, 0x11);
    let taint = TaintGraphIndex::sidecar_path_for_config(&root, 0x22);
    let namespaced = TaintGraphIndex::sidecar_path_for_config_namespace(&root, "taint-analysis", 0x11);

    assert_eq!(TaintGraphIndex::sidecar_path_for_config(&root, 0), legacy);
    assert_ne!(source, legacy);
    assert_ne!(taint, legacy);
    assert_ne!(source, taint);
    assert_ne!(source, namespaced);
    assert!(source
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.contains(".0000000000000011.")));
    assert!(namespaced
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.contains(".taint-analysis.0000000000000011.")));

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn latest_sidecar_path_prefers_configured_sidecars_when_present() {
    let root = tempdir_for("taint-graph-latest-path");
    let legacy = TaintGraphIndex::sidecar_path(&root);
    let configured = TaintGraphIndex::sidecar_path_for_config(&root, 0xfeed);

    assert_eq!(TaintGraphIndex::latest_sidecar_path(&root), legacy);
    std::fs::create_dir_all(configured.parent().expect("configured sidecar parent"))
        .expect("create cache dir");
    std::fs::write(&configured, b"configured").expect("write configured sidecar marker");

    assert_eq!(TaintGraphIndex::latest_sidecar_path(&root), configured);

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn resident_cache_respects_capacity() {
    let idx = TaintGraphIndex::with_capacity(2);
    idx.insert_if_absent(
        FuncId::new(1),
        vec!["a".into()],
        Arc::new(EntryTaintGraph::default()),
    );
    idx.insert_if_absent(
        FuncId::new(2),
        vec!["b".into()],
        Arc::new(EntryTaintGraph::default()),
    );
    idx.insert_if_absent(
        FuncId::new(3),
        vec!["c".into()],
        Arc::new(EntryTaintGraph::default()),
    );

    assert_eq!(idx.resident_capacity(), 2);
    assert_eq!(idx.resident_len(), 2);
    assert!(
        idx.get(FuncId::new(1), &["a".into()]).is_none(),
        "oldest resident graph should be evicted when the cap is exceeded"
    );
    assert!(idx.get(FuncId::new(2), &["b".into()]).is_some());
    assert!(idx.get(FuncId::new(3), &["c".into()]).is_some());
}

#[test]
fn zero_capacity_cache_does_not_retain_graphs() {
    let idx = TaintGraphIndex::with_capacity(0);
    let graph = Arc::new(EntryTaintGraph::default());
    let stored = idx.insert_if_absent(FuncId::new(1), vec!["a".into()], graph.clone());
    assert!(Arc::ptr_eq(&stored, &graph));
    assert_eq!(idx.resident_capacity(), 0);
    assert_eq!(idx.resident_len(), 0);
    assert!(idx.get(FuncId::new(1), &["a".into()]).is_none());
}

#[test]
fn write_through_persists_evicted_graphs() {
    let dir = tempdir_for("bonsai-taint-write-through");
    let path = dir.join("taint_graph.bin");
    let ws = ws_with_python_source("def app(x):\n    return x\n");
    let idx = TaintGraphIndex::with_capacity(1);
    idx.clear_for_config(777);
    idx.begin_persist_to_disk(&path, ws.db(), 777)
        .expect("begin write-through");

    for raw in 1..=3 {
        idx.insert_if_absent(
            FuncId::new(raw),
            vec![format!("seed_{raw}")],
            Arc::new(EntryTaintGraph::default()),
        );
    }
    assert_eq!(idx.resident_len(), 1, "resident cache should stay capped");
    let written = idx.finish_persist_to_disk(ws.db()).expect("finish write-through");
    assert_eq!(written, 3, "all computed graphs should be streamed to disk");

    let restored = TaintGraphIndex::with_capacity(1);
    let loaded = restored
        .load_from_disk_for_config(&path, ws.db(), 777)
        .expect("load write-through sidecar");
    assert_eq!(loaded, 3);
    for raw in 1..=3 {
        assert!(
            restored.get(FuncId::new(raw), &[format!("seed_{raw}")]).is_some(),
            "evicted graph {raw} should still be recoverable from disk"
        );
    }
}

#[test]
fn write_through_sidecar_has_cross_index_single_owner() {
    let dir = tempdir_for("bonsai-taint-write-owner");
    let path = dir.join("taint_graph.bin");
    let ws = ws_with_python_source("def app(x):\n    return x\n");
    let first = TaintGraphIndex::new();
    let second = TaintGraphIndex::new();
    first.clear_for_config(77);
    second.clear_for_config(77);

    assert!(first
        .begin_persist_to_disk(&path, ws.db(), 77)
        .expect("first owner"));
    assert!(!first
        .begin_persist_to_disk(&path, ws.db(), 77)
        .expect("same session is idempotent"));
    let conflict = second
        .begin_persist_to_disk(&path, ws.db(), 77)
        .expect_err("a second Workspace/process must not race the same atomic target");
    assert_eq!(conflict.kind(), std::io::ErrorKind::WouldBlock);

    first
        .finish_persist_to_disk(ws.db())
        .expect("release first owner");
    assert!(second
        .begin_persist_to_disk(&path, ws.db(), 77)
        .expect("lock is released after finish"));
    second
        .finish_persist_to_disk(ws.db())
        .expect("finish second owner");
}

#[test]
fn cleanup_removes_abandoned_taint_graph_temp_files() {
    let dir = tempdir_for("bonsai-taint-temp-cleanup");
    let path = dir.join("taint_graph.bin");
    let abandoned = dir.join("taint_graph.bin.tmp.12345.0");
    let unrelated = dir.join("other.bin.tmp.12345.0");
    std::fs::write(&abandoned, b"partial").expect("write abandoned temp");
    std::fs::write(&unrelated, b"partial").expect("write unrelated temp");

    let removed = cleanup_sidecar_temp_files(&path).expect("cleanup temp files");

    assert_eq!(removed, 1);
    assert!(!abandoned.exists());
    assert!(unrelated.exists());
}

#[test]
fn clear_drops_every_entry() {
    let idx = TaintGraphIndex::new();
    idx.insert_if_absent(
        FuncId::new(1),
        vec!["x".into()],
        Arc::new(EntryTaintGraph::default()),
    );
    idx.insert_if_absent(
        FuncId::new(2),
        vec!["y".into()],
        Arc::new(EntryTaintGraph::default()),
    );
    assert_eq!(idx.len(), 2);
    idx.clear();
    assert!(idx.is_empty());
}

#[test]
fn clear_for_config_invalidates_on_fingerprint_mismatch() {
    let idx = TaintGraphIndex::new();
    idx.clear_for_config(123);
    idx.insert_if_absent(
        FuncId::new(7),
        vec!["k".into()],
        Arc::new(EntryTaintGraph::default()),
    );
    assert_eq!(idx.len(), 1);

    // Same fingerprint → no-op.
    assert!(!idx.clear_for_config(123));
    assert_eq!(idx.len(), 1);

    // Different fingerprint → drops every entry.
    assert!(idx.clear_for_config(456));
    assert!(idx.is_empty());
}

#[test]
fn sidecar_round_trips_via_disk() {
    let dir = tempdir_for("bonsai-taint-sidecar");
    let path = dir.join("taint_graph.bin");

    let original = TaintGraphIndex::new();
    original.clear_for_config(0xc0de_dead_beef);
    original.insert_if_absent(
        FuncId::new(11),
        vec!["alpha".into(), "beta".into()],
        Arc::new(EntryTaintGraph::default()),
    );
    original.insert_if_absent(
        FuncId::new(22),
        vec!["gamma".into()],
        Arc::new(EntryTaintGraph::default()),
    );
    let ws = ws_with_python_source("def app(x):\n    return x\n");
    original.save_to_disk(&path, ws.db()).expect("save sidecar");

    let restored = TaintGraphIndex::new();
    let loaded = restored
        .load_from_disk_for_config(&path, ws.db(), 0xc0de_dead_beef)
        .expect("load sidecar");
    assert_eq!(loaded, 2, "sidecar should restore both entries");
    assert!(restored
        .get(FuncId::new(11), &["alpha".into(), "beta".into()])
        .is_some());
    assert!(restored.get(FuncId::new(22), &["gamma".into()]).is_some());
}

#[test]
fn sidecar_rejects_mismatched_config_fingerprint() {
    let dir = tempdir_for("bonsai-taint-sidecar-mismatch");
    let path = dir.join("taint_graph.bin");

    let original = TaintGraphIndex::new();
    original.clear_for_config(111);
    original.insert_if_absent(
        FuncId::new(11),
        vec!["alpha".into()],
        Arc::new(EntryTaintGraph::default()),
    );
    let ws = ws_with_python_source("def app(x):\n    return x\n");
    original.save_to_disk(&path, ws.db()).expect("save sidecar");

    let restored = TaintGraphIndex::new();
    let loaded = restored
        .load_from_disk_for_config(&path, ws.db(), 222)
        .expect("mismatched sidecar is ignored");
    assert_eq!(loaded, 0, "config mismatch must reject taint graph sidecar");
    assert!(restored.is_empty());
    assert!(
        !path.exists(),
        "stale config-bound sidecar should be removed so future runs do not retain dead cache bytes"
    );
}

#[test]
fn sidecar_rejects_changed_workspace_content() {
    let dir = tempdir_for("bonsai-taint-sidecar-source");
    let path = dir.join("taint_graph.bin");

    let original = TaintGraphIndex::new();
    original.clear_for_config(111);
    original.insert_if_absent(
        FuncId::new(11),
        vec!["alpha".into()],
        Arc::new(EntryTaintGraph::default()),
    );
    let original_ws = ws_with_python_source("def app(x):\n    return x\n");
    original
        .save_to_disk(&path, original_ws.db())
        .expect("save sidecar");

    let changed_ws = ws_with_python_source("def app(x):\n    return x + 1\n");
    let restored = TaintGraphIndex::new();
    let loaded = restored
        .load_from_disk_for_config(&path, changed_ws.db(), 111)
        .expect("changed source sidecar is ignored");
    assert_eq!(loaded, 0, "source mismatch must reject taint graph sidecar");
    assert!(restored.is_empty());
    assert!(
        !path.exists(),
        "stale source-bound taint graph sidecar should be removed after rejection"
    );
}

#[test]
fn sidecar_rejects_changed_dependency_metadata() {
    let root = tempdir_for("bonsai-taint-sidecar-deps");
    let bonsai = root.join(".bonsai");
    std::fs::create_dir(&bonsai).expect("create .bonsai");
    let path = bonsai.join("taint_graph.bin");
    let manifest = root.join("requirements.txt");
    std::fs::write(&manifest, "flask==3.0.0\n").expect("write manifest");

    let original = TaintGraphIndex::new();
    original.clear_for_config(111);
    original.insert_if_absent(
        FuncId::new(11),
        vec!["alpha".into()],
        Arc::new(EntryTaintGraph::default()),
    );
    let ws = ws_with_python_source("def app(x):\n    return x\n");
    original.save_to_disk(&path, ws.db()).expect("save sidecar");

    std::fs::write(&manifest, "flask==3.0.0\nrequests==2.32.0\n").expect("rewrite manifest");
    let restored = TaintGraphIndex::new();
    let loaded = restored
        .load_from_disk_for_config(&path, ws.db(), 111)
        .expect("changed dependency metadata sidecar is ignored");
    assert_eq!(
        loaded, 0,
        "dependency metadata mismatch must reject taint graph sidecar"
    );
    assert!(restored.is_empty());
}

#[test]
fn legacy_loader_rejects_nonzero_config_sidecar() {
    let dir = tempdir_for("bonsai-taint-sidecar-legacy");
    let path = dir.join("taint_graph.bin");

    let original = TaintGraphIndex::new();
    original.clear_for_config(111);
    original.insert_if_absent(
        FuncId::new(11),
        vec!["alpha".into()],
        Arc::new(EntryTaintGraph::default()),
    );
    let ws = ws_with_python_source("def app(x):\n    return x\n");
    original.save_to_disk(&path, ws.db()).expect("save sidecar");

    let restored = TaintGraphIndex::new();
    let loaded = restored
        .load_from_disk(&path, ws.db())
        .expect("legacy loader rejects nonzero config");
    assert_eq!(loaded, 0, "legacy loader must not accept config-bound sidecars");
    assert!(restored.is_empty());
}

#[test]
fn clear_for_config_drops_disk_reader_on_fingerprint_mismatch() {
    let dir = tempdir_for("bonsai-taint-sidecar-clear");
    let path = dir.join("taint_graph.bin");

    let original = TaintGraphIndex::new();
    original.clear_for_config(333);
    original.insert_if_absent(
        FuncId::new(11),
        vec!["alpha".into()],
        Arc::new(EntryTaintGraph::default()),
    );
    let ws = ws_with_python_source("def app(x):\n    return x\n");
    original.save_to_disk(&path, ws.db()).expect("save sidecar");

    let restored = TaintGraphIndex::new();
    let loaded = restored
        .load_from_disk_for_config(&path, ws.db(), 333)
        .expect("load sidecar");
    assert_eq!(loaded, 1);
    assert!(restored.get(FuncId::new(11), &["alpha".into()]).is_some());

    assert!(restored.clear_for_config(444));
    assert!(
        restored.is_empty(),
        "config changes must drop both in-memory entries and disk-backed taint graphs"
    );
}

#[test]
fn sidecar_load_returns_zero_when_path_missing() {
    let dir = tempdir_for("bonsai-taint-missing");
    let path = dir.join("never_written.bin");
    let idx = TaintGraphIndex::new();
    let ws = ws_with_python_source("def app(x):\n    return x\n");
    let loaded = idx.load_from_disk(&path, ws.db()).expect("missing path is ok");
    assert_eq!(loaded, 0);
    assert!(idx.is_empty());
}

#[test]
fn sidecar_with_corrupt_bytes_is_ignored() {
    let dir = tempdir_for("bonsai-taint-corrupt");
    let path = dir.join("taint_graph.bin");
    std::fs::write(&path, b"not a valid factstore payload").expect("write corrupt sidecar");

    let idx = TaintGraphIndex::new();
    let ws = ws_with_python_source("def app(x):\n    return x\n");
    let loaded = idx
        .load_from_disk(&path, ws.db())
        .expect("corrupt path returns Ok(0)");
    assert_eq!(loaded, 0);
    assert!(idx.is_empty());
    assert!(
        !path.exists(),
        "corrupt taint graph sidecar should be removed after rejection"
    );
}
