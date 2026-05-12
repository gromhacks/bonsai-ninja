//! Workspace-wide taint graph index basic round-trip and
//! invalidation. Stage 6 of the eager-graph roadmap; stage 7's
//! sidecar save/load is exercised in `sidecar_round_trip_via_disk`
//! and `sidecar_with_mismatched_version_is_ignored` below.

use bonsai_common::FuncId;
use bonsai_taint::EntryTaintGraph;
use bonsai_workspace::taint_index::TaintGraphIndex;
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
    original.save_to_disk(&path).expect("save sidecar");

    let restored = TaintGraphIndex::new();
    let loaded = restored.load_from_disk(&path).expect("load sidecar");
    assert_eq!(loaded, 2, "sidecar should restore both entries");
    assert!(restored
        .get(FuncId::new(11), &["alpha".into(), "beta".into()])
        .is_some());
    assert!(restored.get(FuncId::new(22), &["gamma".into()]).is_some());
}

#[test]
fn sidecar_load_returns_zero_when_path_missing() {
    let dir = tempdir_for("bonsai-taint-missing");
    let path = dir.join("never_written.bin");
    let idx = TaintGraphIndex::new();
    let loaded = idx.load_from_disk(&path).expect("missing path is ok");
    assert_eq!(loaded, 0);
    assert!(idx.is_empty());
}

#[test]
fn sidecar_with_corrupt_bytes_is_ignored() {
    let dir = tempdir_for("bonsai-taint-corrupt");
    let path = dir.join("taint_graph.bin");
    std::fs::write(&path, b"not a valid bincode payload").expect("write corrupt sidecar");

    let idx = TaintGraphIndex::new();
    let loaded = idx.load_from_disk(&path).expect("corrupt path returns Ok(0)");
    assert_eq!(loaded, 0);
    assert!(idx.is_empty());
}
