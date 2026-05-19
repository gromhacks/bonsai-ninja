//! Workspace-wide dataflow cache tests.
//!
//! Covers Phases 1–4 of the eager taint graph roadmap:
//! - Phase 1: every function's taint facts are precomputed at
//!   `Workspace::open` time (prewarm).
//! - Phase 2: every query that asks for taint facts gets the
//!   precomputed answer (cache hit).
//! - Phase 3: editing a file invalidates the cache; a subsequent
//!   query recomputes the affected entries and agrees with a
//!   fresh-workspace answer.
//! - Phase 4: the cache round-trips through `snapshot` +
//!   `load_snapshot` and survives a process-boundary simulation.
//!
//! Each test runs on a multi-language mini workspace so we catch
//! adapter-specific fallout early.

use bonsai_common::FuncId;
use bonsai_lang_api::{AdapterArc, LanguageRegistry};
use bonsai_vfs::Vfs;
use bonsai_workspace::{dataflow::DataFlowCache, Workspace, WorkspaceOpenOptions};
use std::collections::HashSet;
use std::sync::Arc;

fn ws_with(files: &[(&str, &str)], adapter: AdapterArc) -> Workspace {
    let registry = Arc::new(LanguageRegistry::new());
    registry.register(adapter);
    let ws = Workspace::new(registry);
    for (p, src) in files {
        ws.vfs().write((*p).to_string(), Arc::<str>::from(*src));
    }
    for f in ws.vfs().all_files() {
        let _ = ws.db().decl_index(f);
    }
    // Match what `Workspace::open` does after indexing.
    ws.dataflow().prewarm_all(ws.db());
    ws
}

fn python_adapter() -> AdapterArc {
    Arc::new(bonsai_lang_python::PythonAdapter::new())
}

fn js_adapter() -> AdapterArc {
    Arc::new(bonsai_lang_javascript::JavaScriptAdapter::new())
}

fn rust_adapter() -> AdapterArc {
    Arc::new(bonsai_lang_rust::RustAdapter::new())
}

fn tempdir(name: &str) -> std::path::PathBuf {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "bonsai-workspace-dataflow-{name}-{}-{stamp}",
        std::process::id()
    ));
    std::fs::create_dir(&path).expect("create temp dir");
    path
}

fn func_id_by_name(ws: &Workspace, name: &str) -> FuncId {
    let global = ws.db().global_index();
    let syms = global.find_by_name(name);
    let sym = syms
        .iter()
        .find(|s| {
            global.decl_of(**s).is_some_and(|d| {
                matches!(
                    d.kind,
                    bonsai_lang_api::DeclKind::Function
                        | bonsai_lang_api::DeclKind::Method
                        | bonsai_lang_api::DeclKind::Constructor
                )
            })
        })
        .unwrap_or_else(|| panic!("no function named `{name}` in workspace"));
    FuncId::new(sym.raw())
}

// ===========================================================================
// Phase 1 — prewarm populates every function
// ===========================================================================

#[test]
fn prewarm_populates_every_function_python() {
    let ws = ws_with(
        &[(
            "/w/m.py",
            "def handle(req):\n    update(req)\ndef update(x):\n    sink(x)\ndef sink(y):\n    pass\n",
        )],
        python_adapter(),
    );
    // Every indexed function should have a cache entry after prewarm.
    let global = ws.db().global_index();
    let funcs: Vec<FuncId> = global
        .all_files()
        .flat_map(|f| {
            global
                .decls_in(f)
                .iter()
                .filter(|d| {
                    matches!(
                        d.kind,
                        bonsai_lang_api::DeclKind::Function
                            | bonsai_lang_api::DeclKind::Method
                            | bonsai_lang_api::DeclKind::Constructor
                    )
                })
                .map(|d| FuncId::new(d.symbol.raw()))
                .collect::<Vec<_>>()
        })
        .collect();
    assert!(ws.dataflow().is_prewarmed(), "prewarm flag must be set");
    assert_eq!(
        ws.dataflow().len(),
        funcs.len(),
        "cache should hold one entry per function"
    );
}

#[test]
fn prewarm_populates_every_function_javascript() {
    let ws = ws_with(
        &[(
            "/w/m.js",
            "export function handle(req) { update(req); }\n\
             export function update(x) { sink(x); }\n\
             export function sink(y) {}\n",
        )],
        js_adapter(),
    );
    assert!(ws.dataflow().is_prewarmed());
    assert!(ws.dataflow().len() >= 3, "three functions must be cached");
}

#[test]
fn prewarm_populates_every_function_rust() {
    let ws = ws_with(
        &[(
            "/w/m.rs",
            "pub fn handle(req: String) { update(req); }\n\
             pub fn update(x: String) { sink(x); }\n\
             pub fn sink(_y: String) {}\n",
        )],
        rust_adapter(),
    );
    assert!(ws.dataflow().is_prewarmed());
    assert!(ws.dataflow().len() >= 3);
}

// ===========================================================================
// Phase 2 — queries hit the cache and match on-demand computation
// ===========================================================================

#[test]
fn cache_hit_matches_fresh_computation() {
    // `handle → update → sink`: param `req` taints `x` taints `y`.
    // A cached query for `handle` must agree with a fresh (no-cache)
    // interprocedural run for the same entry.
    let src = "def handle(req):\n    update(req)\ndef update(x):\n    sink(x)\ndef sink(y):\n    pass\n";
    let ws = ws_with(&[("/w/m.py", src)], python_adapter());
    let handle = func_id_by_name(&ws, "handle");
    let cached = ws.dataflow().facts_for(handle, ws.db());
    // Fresh cache for sanity: skip prewarm, query once.
    let fresh_cache = DataFlowCache::new();
    let fresh = fresh_cache.facts_for(handle, ws.db());
    assert_eq!(
        cached.flattened(),
        fresh.flattened(),
        "cached and fresh results must agree token-for-token"
    );
    // Cross-module taint must have reached `update`/`sink`/their params.
    let tokens = cached.flattened();
    assert!(
        tokens
            .iter()
            .any(|t| t == "update" || t == "sink" || t == "x" || t == "y"),
        "expected propagated tokens; got {tokens:?}"
    );
}

#[test]
fn cache_clear_forces_recompute_and_agrees() {
    let ws = ws_with(
        &[(
            "/w/m.py",
            "def handle(req):\n    sink(req)\ndef sink(y):\n    pass\n",
        )],
        python_adapter(),
    );
    let handle = func_id_by_name(&ws, "handle");
    let first = ws.dataflow().facts_for(handle, ws.db());
    ws.dataflow().clear();
    let second = ws.dataflow().facts_for(handle, ws.db());
    assert_eq!(
        first.flattened(),
        second.flattened(),
        "clear+recompute must produce identical facts"
    );
}

// ===========================================================================
// Indexed graph mode — graph records are built at index and queryable later
// ===========================================================================

#[test]
fn graph_for_contains_tainted_edges_and_sink_calls_after_prewarm() {
    let ws = ws_with(
        &[(
            "/w/m.py",
            "def handle(req):\n    mid(req)\ndef mid(x):\n    sink(x)\ndef sink(y):\n    pass\n",
        )],
        python_adapter(),
    );
    let handle = func_id_by_name(&ws, "handle");
    let mid = func_id_by_name(&ws, "mid");
    let sink = func_id_by_name(&ws, "sink");

    let graph = ws.dataflow().graph_for(handle, ws.db());
    assert!(
        graph
            .call_records
            .iter()
            .any(|edge| edge.caller == handle && edge.callee == mid),
        "indexed graph should contain handle -> mid tainted edge: {:?}",
        graph.call_records
    );
    assert!(
        graph
            .call_records
            .iter()
            .any(|edge| edge.caller == mid && edge.callee == sink),
        "indexed graph should contain mid -> sink tainted edge: {:?}",
        graph.call_records
    );
    assert!(
        graph
            .tainted_calls
            .iter()
            .any(|call| call.caller == mid && call.name == "sink"),
        "indexed graph should expose the tainted sink call site: {:?}",
        graph.tainted_calls
    );
}

#[test]
fn snapshot_roundtrip_preserves_structured_taint_graph() {
    let src = "def handle(req):\n    mid(req)\ndef mid(x):\n    sink(x)\ndef sink(y):\n    pass\n";
    let ws = ws_with(&[("/w/m.py", src)], python_adapter());
    let handle = func_id_by_name(&ws, "handle");
    let before = ws.dataflow().graph_for(handle, ws.db());
    assert!(
        !before.call_records.is_empty() && !before.tainted_calls.is_empty(),
        "fixture must produce structured graph records before snapshot"
    );

    let snap = ws.dataflow().snapshot(ws.db());
    let bytes = bincode::serialize(&snap).expect("bincode serialise");
    let decoded: bonsai_workspace::dataflow::SerializableSnapshot =
        bincode::deserialize(&bytes).expect("bincode deserialise");

    let registry = Arc::new(LanguageRegistry::new());
    registry.register(python_adapter());
    let ws2 = Workspace::new(registry);
    ws2.vfs().write("/w/m.py".to_string(), Arc::<str>::from(src));
    for f in ws2.vfs().all_files() {
        let _ = ws2.db().decl_index(f);
    }
    let surviving = ws2.dataflow().load_snapshot(decoded, ws2.db());
    assert!(surviving > 0, "same-content reload should preserve graph entries");

    let handle2 = func_id_by_name(&ws2, "handle");
    let mid2 = func_id_by_name(&ws2, "mid");
    let sink2 = func_id_by_name(&ws2, "sink");
    let restored = ws2.dataflow().graph_for(handle2, ws2.db());
    assert!(
        restored
            .call_records
            .iter()
            .any(|edge| edge.caller == handle2 && edge.callee == mid2),
        "restored graph should remap handle -> mid to fresh FuncIds: {:?}",
        restored.call_records
    );
    assert!(
        restored
            .call_records
            .iter()
            .any(|edge| edge.caller == mid2 && edge.callee == sink2),
        "restored graph should remap mid -> sink to fresh FuncIds: {:?}",
        restored.call_records
    );
    assert!(
        restored
            .tainted_calls
            .iter()
            .any(|call| call.caller == mid2 && call.name == "sink"),
        "restored graph should preserve tainted call sites with fresh FuncIds: {:?}",
        restored.tainted_calls
    );
}

#[test]
fn snapshot_interns_file_paths_and_dependency_metadata() {
    let controller_path = "/w/services/api/controllers/really_long_controller_module.py";
    let sink_path = "/w/services/security/sinks/really_long_sink_module.py";
    let mut controller = String::new();
    controller.push_str("from really_long_sink_module import sink\n\n");
    for i in 0..12 {
        controller.push_str(&format!("def handle_{i}(req):\n    sink(req)\n\n"));
    }
    let ws = ws_with(
        &[
            (controller_path, controller.as_str()),
            (sink_path, "def sink(value):\n    pass\n"),
        ],
        python_adapter(),
    );

    let snap = ws.dataflow().snapshot(ws.db());
    assert_eq!(
        snap.files.len(),
        2,
        "snapshot should store each workspace file once: {:?}",
        snap.files
    );
    let unique_paths: HashSet<&str> = snap.files.iter().map(|file| file.path.as_str()).collect();
    assert_eq!(
        unique_paths.len(),
        snap.files.len(),
        "snapshot file table must not contain duplicate paths"
    );
    assert!(
        snap.entries.len() >= 13,
        "fixture should produce many functions so repeated paths would be costly"
    );

    for entry in &snap.entries {
        assert!(
            (entry.file_index as usize) < snap.files.len(),
            "entry file_index must point into snapshot file table: {entry:?}"
        );
        for &dep in &entry.dependencies {
            assert!(
                (dep as usize) < snap.files.len(),
                "dependency index must point into snapshot file table: {entry:?}"
            );
        }
    }

    let handle = snap
        .entries
        .iter()
        .find(|entry| entry.func_name == "handle_0")
        .expect("handle_0 entry");
    let dependency_paths: HashSet<&str> = handle
        .dependencies
        .iter()
        .map(|&idx| snap.files[idx as usize].path.as_str())
        .collect();
    assert!(
        dependency_paths.contains(controller_path) && dependency_paths.contains(sink_path),
        "cross-file entry should depend on both declaring and downstream files: {dependency_paths:?}"
    );

    let repeated_path_bytes: usize = snap
        .entries
        .iter()
        .map(|entry| {
            snap.files[entry.file_index as usize].path.len()
                + entry
                    .dependencies
                    .iter()
                    .map(|&idx| snap.files[idx as usize].path.len())
                    .sum::<usize>()
        })
        .sum();
    let interned_path_bytes: usize = snap.files.iter().map(|file| file.path.len()).sum();
    assert!(
        interned_path_bytes * 2 < repeated_path_bytes,
        "interned file table should be substantially smaller than repeating paths per entry \
         (interned={interned_path_bytes}, repeated={repeated_path_bytes})"
    );
}

#[test]
fn snapshot_rejects_malformed_file_indexes_without_panic() {
    let src = "def handle(req):\n    sink(req)\ndef sink(y):\n    pass\n";
    let ws = ws_with(&[("/w/m.py", src)], python_adapter());
    let mut snap = ws.dataflow().snapshot(ws.db());
    assert!(!snap.entries.is_empty(), "fixture must produce persisted entries");
    for entry in &mut snap.entries {
        entry.dependencies.push(u32::MAX);
    }

    let registry = Arc::new(LanguageRegistry::new());
    registry.register(python_adapter());
    let ws2 = Workspace::new(registry);
    ws2.vfs().write("/w/m.py".to_string(), Arc::<str>::from(src));
    for f in ws2.vfs().all_files() {
        let _ = ws2.db().decl_index(f);
    }

    let surviving = ws2.dataflow().load_snapshot(snap, ws2.db());
    assert_eq!(
        surviving, 0,
        "malformed dependency indexes must be treated as stale cache entries"
    );
}

#[test]
fn sanitizer_profile_compatibility_does_not_change_indexed_graph_scope() {
    let ws = ws_with(
        &[(
            "/w/m.py",
            "def handle(req):\n\
    mid(req)\n\
def mid(x):\n\
    sink(x)\n\
def sink(y):\n\
    pass\n",
        )],
        python_adapter(),
    );
    let global = ws.db().global_index();
    let func_count = global
        .all_files()
        .flat_map(|f| global.decls_in(f).to_vec())
        .filter(|d| {
            matches!(
                d.kind,
                bonsai_lang_api::DeclKind::Function
                    | bonsai_lang_api::DeclKind::Method
                    | bonsai_lang_api::DeclKind::Constructor
            )
        })
        .count();
    let mut sanitizers = bonsai_taint::TokenSet::default();
    sanitizers.insert("clean".to_string());
    assert_eq!(
        ws.dataflow().pending_count_with_sanitizers(ws.db(), &sanitizers),
        0,
        "compatibility sanitizer argument should not create work after canonical prewarm"
    );
    ws.dataflow().clear();
    assert_eq!(
        ws.dataflow().pending_count_with_sanitizers(ws.db(), &sanitizers),
        func_count,
        "compatibility sanitizer argument should use the same cold graph scope"
    );
    ws.dataflow().prewarm_all_with_sanitizers(ws.db(), &sanitizers);
    assert_eq!(
        ws.dataflow().pending_count_with_sanitizers(ws.db(), &sanitizers),
        0,
        "prewarm should populate the canonical graph regardless of sanitizer names"
    );
    assert_eq!(
        ws.dataflow().pending_count(ws.db()),
        0,
        "sanitizer names must not create a separate graph profile"
    );
    let snap = ws.dataflow().snapshot(ws.db());
    assert_ne!(
        snap.sanitizer_fingerprint, 0,
        "snapshot keeps a non-zero compatibility fingerprint for the canonical graph"
    );
    assert_eq!(
        snap.matcher_policy_fingerprint,
        bonsai_common::MATCHER_POLICY_FINGERPRINT,
        "snapshot records the current matcher policy fingerprint"
    );
    assert!(
        snap.sanitizer_tokens.is_empty(),
        "sanitizer names are reporting evidence, not sidecar graph inputs"
    );
}

#[test]
fn snapshot_rejects_stale_matcher_policy_fingerprint() {
    let src = "def handle(req):\n    sink(req)\ndef sink(y):\n    pass\n";
    let ws = ws_with(&[("/w/m.py", src)], python_adapter());
    let mut snap = ws.dataflow().snapshot(ws.db());
    assert!(!snap.entries.is_empty(), "fixture must produce persisted entries");
    snap.matcher_policy_fingerprint ^= 1;

    let ws2 = ws_with(&[("/w/m.py", src)], python_adapter());
    let surviving = ws2.dataflow().load_snapshot(snap, ws2.db());
    assert_eq!(
        surviving, 0,
        "sidecar entries must be rejected after matcher policy drift"
    );
}

#[test]
fn factstore_sidecar_rejects_dependency_metadata_change() {
    let root = tempdir("dependency-metadata");
    std::fs::write(
        root.join("app.py"),
        "def handle(req):\n    sink(req)\ndef sink(value):\n    pass\n",
    )
    .expect("write source");
    std::fs::write(root.join("requirements.txt"), "flask==3.0.0\n").expect("write deps");

    let registry = Arc::new(LanguageRegistry::new());
    registry.register(python_adapter());
    let options = WorkspaceOpenOptions {
        load_dataflow_sidecar: false,
        prewarm_dataflow: true,
        save_dataflow_sidecar: true,
        load_value_flow_sidecar: false,
        prewarm_value_flow: false,
        save_value_flow_sidecar: false,
        prewarm_flow_ids: false,
        parse_timeout_ms: None,
    };
    let _indexed = Workspace::open_with_options(&root, registry.clone(), options).expect("index workspace");
    let sidecar = DataFlowCache::factstore_sidecar_path(&root);
    assert!(sidecar.exists(), "index should write dataflow factstore");

    std::fs::write(root.join("requirements.txt"), "flask==3.0.0\nrequests==2.32.0\n").expect("rewrite deps");
    let query_ws = Workspace::open_with_options(&root, registry, WorkspaceOpenOptions::parse_only())
        .expect("open query ws");
    let loaded = query_ws
        .dataflow()
        .load_factstore_sidecar(&sidecar, query_ws.db())
        .expect("load sidecar");
    assert_eq!(
        loaded, 0,
        "dependency metadata changes must reject persisted analysis sidecars"
    );

    std::fs::remove_dir_all(&root).ok();
}

// ===========================================================================
// Phase 3 — file edits invalidate the cache; subsequent queries are fresh
// ===========================================================================

#[test]
fn file_edit_invalidates_and_recomputes() {
    // Start with a flow that DOES propagate taint.
    let ws = ws_with(
        &[(
            "/w/m.py",
            "def handle(req):\n    sink(req)\ndef sink(y):\n    pass\n",
        )],
        python_adapter(),
    );
    let handle = func_id_by_name(&ws, "handle");
    let before = ws.dataflow().facts_for(handle, ws.db()).flattened();
    assert!(!before.is_empty(), "pre-edit should have propagated tokens");

    // Rewrite the same file so `handle` no longer calls `sink`.
    ws.apply_edit(
        std::path::Path::new("/w/m.py"),
        "def handle(req):\n    pass\ndef sink(y):\n    pass\n".to_string(),
    );
    // After the edit the dataflow cache is invalidated (hooked into
    // `apply_edit`). A fresh query should recompute against the new
    // source.
    assert!(
        !ws.dataflow().is_prewarmed(),
        "prewarm flag should clear after edit"
    );
    let handle_post = func_id_by_name(&ws, "handle");
    let after = ws.dataflow().facts_for(handle_post, ws.db()).flattened();
    // The post-edit `handle` no longer calls sink — no cross-function
    // propagation is possible, so the returned set must shrink (or
    // be empty).
    assert!(
        after.is_subset(&before) || after.len() <= before.len(),
        "post-edit taint facts must not grow; before={before:?} after={after:?}"
    );
}

#[test]
fn file_edit_preserves_unrelated_cached_entries() {
    let ws = ws_with(
        &[
            (
                "/w/a.py",
                "def handle_a(req):\n    sink_a(req)\ndef sink_a(y):\n    pass\n",
            ),
            (
                "/w/b.py",
                "def handle_b(req):\n    sink_b(req)\ndef sink_b(y):\n    pass\n",
            ),
        ],
        python_adapter(),
    );
    let before_len = ws.dataflow().len();
    assert!(before_len >= 4, "fixture should cache both files' functions");

    ws.apply_edit(
        std::path::Path::new("/w/a.py"),
        "def handle_a(req):\n    pass\ndef sink_a(y):\n    pass\n".to_string(),
    );

    let after_len = ws.dataflow().len();
    assert!(
        after_len > 0 && after_len < before_len,
        "editing one file should evict dependent entries only; before={before_len} after={after_len}"
    );
    let handle_b = func_id_by_name(&ws, "handle_b");
    let facts_b = ws.dataflow().facts_for(handle_b, ws.db());
    assert!(
        facts_b
            .flattened()
            .iter()
            .any(|token| token == "sink_b" || token == "y"),
        "unrelated cached path should remain queryable after a.py edit"
    );
}

#[test]
fn corrupt_sidecar_loads_as_empty_cache() {
    let ws = ws_with(
        &[(
            "/w/m.py",
            "def handle(req):\n    sink(req)\ndef sink(y):\n    pass\n",
        )],
        python_adapter(),
    );
    let unique = format!(
        "bonsai-dataflow-corrupt-{}-{:?}",
        std::process::id(),
        std::time::SystemTime::now()
    );
    let dir = std::env::temp_dir().join(unique);
    std::fs::create_dir_all(&dir).expect("create temp dataflow dir");
    let sidecar = dir.join("dataflow.v2.bin");
    std::fs::write(&sidecar, b"not a bincode sidecar").expect("write corrupt sidecar");

    let loaded = ws
        .dataflow()
        .load_from_disk(&sidecar, ws.db())
        .expect("corrupt sidecar is non-fatal");
    assert_eq!(loaded, 0);

    std::fs::remove_dir_all(dir).expect("remove temp dataflow dir");
}

// ===========================================================================
// Phase 4 — snapshot round-trip keeps identical results
// ===========================================================================

#[test]
fn snapshot_roundtrip_preserves_facts() {
    let ws = ws_with(
        &[(
            "/w/m.py",
            "def handle(req):\n    sink(req)\ndef sink(y):\n    pass\n",
        )],
        python_adapter(),
    );
    let handle = func_id_by_name(&ws, "handle");
    let before = ws.dataflow().facts_for(handle, ws.db()).flattened();
    let snap = ws.dataflow().snapshot(ws.db());
    let bytes = bincode::serialize(&snap).expect("bincode serialise");
    let decoded: bonsai_workspace::dataflow::SerializableSnapshot =
        bincode::deserialize(&bytes).expect("bincode deserialise");

    // Reconstruct a fresh workspace from the SAME sources and load
    // the snapshot — mimics "process restart, sidecar present."
    let registry = Arc::new(LanguageRegistry::new());
    registry.register(python_adapter());
    let ws2 = Workspace::new(registry);
    ws2.vfs().write(
        "/w/m.py".to_string(),
        Arc::<str>::from("def handle(req):\n    sink(req)\ndef sink(y):\n    pass\n"),
    );
    for f in ws2.vfs().all_files() {
        let _ = ws2.db().decl_index(f);
    }
    let surviving = ws2.dataflow().load_snapshot(decoded, ws2.db());
    assert!(
        surviving > 0,
        "at least one entry should survive a same-content reload"
    );
    let handle2 = func_id_by_name(&ws2, "handle");
    let restored = ws2.dataflow().facts_for(handle2, ws2.db()).flattened();
    assert_eq!(
        before, restored,
        "snapshot round-trip must yield identical taint tokens"
    );
}

#[test]
fn snapshot_rejects_version_mismatch() {
    let ws = ws_with(
        &[(
            "/w/m.py",
            "def handle(req):\n    sink(req)\ndef sink(y):\n    pass\n",
        )],
        python_adapter(),
    );
    let mut snap = ws.dataflow().snapshot(ws.db());
    snap.version = u32::MAX; // force a mismatch
    let registry = Arc::new(LanguageRegistry::new());
    registry.register(python_adapter());
    let ws2 = Workspace::new(registry);
    for _ in ws2.vfs().all_files() {}
    let surviving = ws2.dataflow().load_snapshot(snap, ws2.db());
    assert_eq!(surviving, 0, "version mismatch must drop every entry");
}

#[test]
fn snapshot_rejects_changed_file_contents() {
    let ws = ws_with(
        &[(
            "/w/m.py",
            "def handle(req):\n    sink(req)\ndef sink(y):\n    pass\n",
        )],
        python_adapter(),
    );
    let snap = ws.dataflow().snapshot(ws.db());

    // Rebuild with different contents; the file-content hash won't
    // match, so every entry should drop out.
    let vfs = Arc::new(Vfs::new());
    vfs.write(
        "/w/m.py".to_string(),
        Arc::<str>::from("def other(z):\n    pass\n"),
    );
    let registry = Arc::new(LanguageRegistry::new());
    registry.register(python_adapter());
    let ws2 = {
        let ws2 = Workspace::new(registry);
        ws2.vfs().write(
            "/w/m.py".to_string(),
            Arc::<str>::from("def other(z):\n    pass\n"),
        );
        for f in ws2.vfs().all_files() {
            let _ = ws2.db().decl_index(f);
        }
        ws2
    };
    let surviving = ws2.dataflow().load_snapshot(snap, ws2.db());
    assert_eq!(
        surviving, 0,
        "changed file contents must invalidate every snapshotted entry"
    );
    drop(vfs);
}

#[test]
fn snapshot_rejects_same_function_after_body_change() {
    let ws = ws_with(
        &[(
            "/w/m.py",
            "def handle(req):\n    sink(req)\ndef sink(y):\n    pass\n",
        )],
        python_adapter(),
    );
    let snap = ws.dataflow().snapshot(ws.db());

    let registry = Arc::new(LanguageRegistry::new());
    registry.register(python_adapter());
    let ws2 = Workspace::new(registry);
    ws2.vfs().write(
        "/w/m.py".to_string(),
        Arc::<str>::from("def handle(req):\n    pass\ndef sink(y):\n    pass\n"),
    );
    for f in ws2.vfs().all_files() {
        let _ = ws2.db().decl_index(f);
    }

    let surviving = ws2.dataflow().load_snapshot(snap, ws2.db());
    assert_eq!(
        surviving, 0,
        "changed file content must invalidate persisted facts even when function names and spans still match"
    );
}

#[test]
fn snapshot_rejects_entry_when_downstream_file_changes() {
    let ws = ws_with(
        &[
            (
                "/w/a.py",
                "from b import sink\n\ndef handle(req):\n    sink(req)\n",
            ),
            ("/w/b.py", "def sink(y):\n    pass\n"),
        ],
        python_adapter(),
    );
    let snap = ws.dataflow().snapshot(ws.db());

    let registry = Arc::new(LanguageRegistry::new());
    registry.register(python_adapter());
    let ws2 = Workspace::new(registry);
    ws2.vfs().write(
        "/w/a.py".to_string(),
        Arc::<str>::from("from b import sink\n\ndef handle(req):\n    sink(req)\n"),
    );
    ws2.vfs().write(
        "/w/b.py".to_string(),
        Arc::<str>::from("def sink(y):\n    cleaned = y\n    return cleaned\n"),
    );
    for f in ws2.vfs().all_files() {
        let _ = ws2.db().decl_index(f);
    }

    let surviving = ws2.dataflow().load_snapshot(snap, ws2.db());
    assert_eq!(
        surviving, 0,
        "entry facts must be rejected when a downstream dependency file changes"
    );
}
