//! Concurrency regression tests for the workspace caches. Cold paths must
//! drop read guards before taking write guards: an `if let
//! Some(_) = lock.read().get(...).cloned()` scrutinee can retain its
//! temporary into a later `lock.write()` and deadlock the same thread under
//! `parking_lot::RwLock`. Cold construction is also single-flight or
//! snapshot-keyed so an old source snapshot cannot repopulate a cache
//! after edit invalidation.
//!
//! A regression that re-introduces the if-let-scrutinee form
//! would deadlock the workers and trip the timeout below.

use bonsai_common::FuncId;
use bonsai_lang_api::{AdapterArc, LanguageRegistry};
use bonsai_workspace::{Workspace, WorkspaceOpenOptions};
use rayon::prelude::*;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const PARALLEL_HITS: usize = 64;
const DEADLINE: Duration = Duration::from_secs(15);

fn registry() -> Arc<LanguageRegistry> {
    let r = Arc::new(LanguageRegistry::new());
    let adapter: AdapterArc = Arc::new(bonsai_lang_python::PythonAdapter::new());
    r.register(adapter);
    r
}

fn tempdir_for_test(name: &str) -> PathBuf {
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

fn write_python_workspace(root: &std::path::Path) {
    let body = "def helper():\n    return input()\n\n\
def consumer(value):\n    return value.strip()\n\n\
def caller():\n    raw = helper()\n    cleaned = consumer(raw)\n    return cleaned\n\n\
class Box:\n    def value(self):\n        return 0\n";
    std::fs::write(root.join("app.py"), body).expect("write fixture");
}

/// Build a fresh, empty (un-prewarmed) workspace so the first cache
/// access from each worker has to take the cold path.
fn fresh_workspace() -> (Workspace, FuncId) {
    let root = tempdir_for_test("bonsai-cache-concurrency");
    write_python_workspace(&root);
    let ws = Workspace::open_with_options(&root, registry(), WorkspaceOpenOptions::query_only())
        .expect("open succeeds");
    let global = ws.compiler_linkage_index();
    let caller_sym = global
        .find_by_name("caller")
        .iter()
        .copied()
        .next()
        .expect("caller decl present");
    let caller_func = FuncId::new(caller_sym.raw());
    (ws, caller_func)
}

fn assert_finishes_within<F: FnOnce() + Send>(name: &str, body: F) {
    let started = Instant::now();
    let (tx, rx) = std::sync::mpsc::sync_channel::<()>(1);
    std::thread::scope(|scope| {
        scope.spawn(move || {
            body();
            let _ = tx.send(());
        });
        match rx.recv_timeout(DEADLINE) {
            Ok(()) => {
                let elapsed = started.elapsed();
                assert!(
                    elapsed < DEADLINE,
                    "{name}: completed but took {elapsed:?} (>= {DEADLINE:?})"
                );
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => panic!(
                "{name}: deadlocked or hung — no completion within {DEADLINE:?}; \
                 likely re-introduced read-then-write RwLock hazard"
            ),
            Err(other) => panic!("{name}: unexpected channel error: {other:?}"),
        }
    });
}

#[test]
fn value_flow_cache_no_deadlock_under_parallel_cold_hits() {
    let (ws, caller_func) = fresh_workspace();
    assert_finishes_within("ValueFlowCache::graph_for_with_caches", || {
        (0..PARALLEL_HITS).into_par_iter().for_each(|_| {
            let _ = ws
                .value_flow()
                .graph_for_with_caches(caller_func, ws.db(), ws.inter_taint_caches());
        });
    });
}

#[test]
fn dataflow_cache_no_deadlock_under_parallel_cold_hits() {
    let (ws, caller_func) = fresh_workspace();
    assert_finishes_within("DataFlowCache::facts_for", || {
        (0..PARALLEL_HITS).into_par_iter().for_each(|_| {
            let _ = ws.dataflow().facts_for(caller_func, ws.db());
        });
    });
}

#[test]
fn cached_resolved_call_graph_no_deadlock_under_parallel_cold_hits() {
    let (ws, _func) = fresh_workspace();
    assert_finishes_within("Workspace::cached_resolved_call_graph", || {
        (0..PARALLEL_HITS).into_par_iter().for_each(|_| {
            let _ = ws.cached_resolved_call_graph();
        });
    });
}

#[test]
fn class_member_index_no_deadlock_under_parallel_cold_hits() {
    let (ws, _func) = fresh_workspace();
    let global = ws.compiler_linkage_index();
    let class_sym = global
        .find_by_name("Box")
        .iter()
        .copied()
        .next()
        .expect("class Box present");
    assert_finishes_within("ClassMemberIndex::methods_of", || {
        (0..PARALLEL_HITS).into_par_iter().for_each(|_| {
            let _ = ws.class_members().methods_of(&global, class_sym, "value");
        });
    });
}

#[test]
fn enclosing_index_no_deadlock_under_parallel_cold_hits() {
    let (ws, _func) = fresh_workspace();
    let file = ws.vfs().all_files()[0];
    let headers = ws.compiler_linkage_index();
    assert_finishes_within("EnclosingIndex::entries_for", || {
        (0..PARALLEL_HITS).into_par_iter().for_each(|_| {
            let _ = ws.enclosing_index().entries_for(headers.as_ref(), file);
        });
    });
}

#[test]
fn decl_name_index_no_deadlock_under_parallel_cold_hits() {
    let (ws, _func) = fresh_workspace();
    let headers = ws.compiler_linkage_index();
    assert_finishes_within("DeclNameIndex::entries", || {
        (0..PARALLEL_HITS).into_par_iter().for_each(|_| {
            let _ = ws.decl_name_index().entries(headers.as_ref());
        });
    });
}

#[test]
fn flow_ids_cache_no_deadlock_under_parallel_cold_hits() {
    let (ws, caller_func) = fresh_workspace();
    assert_finishes_within("FlowIdCache::id_for_func", || {
        (0..PARALLEL_HITS).into_par_iter().for_each(|_| {
            let _ = ws.flow_ids().id_for_func(caller_func, ws.db(), ws.vfs());
        });
    });
}
