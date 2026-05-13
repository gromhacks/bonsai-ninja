//! Phase 7: hot-reload semantics for the workspace IDG.
//!
//! Asserts that after a file edit, the IDG service is correctly
//! invalidated and the next query reflects the new file content. The
//! current implementation drops the IDG service slot wholesale on
//! file edit and lazy-rebuilds on next access — this test pins that
//! behaviour so any future incremental-rebuild optimisation
//! (per-file segment replacement) preserves correctness.
//!
//! The deeper "rebuild only the changed segment" optimisation lives
//! in `bonsai_idg::workspace::IdgWorkspace::cross_file()` /
//! `invalidate_from_segment` and is exercised by the IDG crate's own
//! `hot_reload_invalidates_only_affected_cross_file_edges` integration
//! test. Here we cover the workspace-facing contract: the value-flow
//! cache plus the IDG service stay coherent across a file refresh.

use std::path::PathBuf;
use std::sync::Arc;

use bonsai_lang_api::LanguageRegistry;
use bonsai_workspace::{Workspace, WorkspaceOpenOptions};

fn registry() -> Arc<LanguageRegistry> {
    let registry = LanguageRegistry::new();
    registry.register(Arc::new(bonsai_lang_python::PythonAdapter::new()));
    Arc::new(registry)
}

fn write_file(dir: &PathBuf, name: &str, content: &str) {
    std::fs::write(dir.join(name), content).expect("write fixture");
}

#[test]
fn idg_service_invalidated_then_rebuilt_after_file_edit() {
    let tmp = std::env::temp_dir().join(format!(
        "bonsai-idg-hot-reload-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).expect("create tmp dir");

    write_file(
        &tmp,
        "app.py",
        "def f(x):\n    helper(x)\n\ndef helper(p):\n    sink(p)\n",
    );
    let ws =
        Workspace::open_with_options(&tmp, registry(), WorkspaceOpenOptions::default()).expect("open ws");

    // First fetch: IDG is built and seeded by the open path.
    let svc1 = ws.db().idg_service().expect("idg seeded after open");
    let segment_count_1 = svc1.segment_count();
    let intra_edges_1 = svc1.intra_edge_count();
    assert!(segment_count_1 >= 1);
    assert!(intra_edges_1 > 0);

    // Edit the file: rewrite its body to add a second helper. The
    // IDG should reflect the new structure on next query.
    write_file(
        &tmp,
        "app.py",
        "def f(x):\n    helper(x)\n    second(x)\n\ndef helper(p):\n    sink(p)\n\ndef second(q):\n    sink(q)\n",
    );
    let _ = ws.refresh_file_from_disk(&tmp.join("app.py")).expect("refresh");

    // After the edit the slot is dropped (`invalidate_idg_service`)
    // until the next caller asks for it.
    assert!(
        ws.db().idg_service().is_none(),
        "expected IDG slot empty after file edit, got Some"
    );

    // Lazy rebuild via the public helper.
    let svc2 = ws.build_and_seed_idg_service();
    assert!(
        svc2.segment_count() >= 1,
        "post-edit IDG must have at least one segment"
    );
    assert!(
        svc2.intra_edge_count() > intra_edges_1,
        "edited file added a second helper + call site, edge count must grow ({} → {})",
        intra_edges_1,
        svc2.intra_edge_count(),
    );

    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn idg_sidecar_written_on_open_then_reloaded_on_reopen() {
    // The CodeQL-style index/query split relies on the IDG sidecar
    // surviving across process boundaries. Open twice: the first open
    // builds and writes `.bonsai/idg.v1.factstore`; the second open
    // hits the load_from_disk fast path. Both must agree on segment
    // count + edge count.
    let tmp = std::env::temp_dir().join(format!(
        "bonsai-idg-sidecar-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).expect("create tmp dir");
    write_file(
        &tmp,
        "app.py",
        "def f(x):\n    helper(x)\n\ndef helper(p):\n    sink(p)\n",
    );

    let ws1 = Workspace::open_with_options(&tmp, registry(), WorkspaceOpenOptions::default())
        .expect("first open");
    let svc1 = ws1.db().idg_service().expect("idg seeded after first open");
    let segments_1 = svc1.segment_count();
    let edges_1 = svc1.intra_edge_count();

    let sidecar = tmp.join(".bonsai").join("idg.v1.factstore");
    assert!(
        sidecar.exists(),
        "expected IDG sidecar at {} after open",
        sidecar.display()
    );

    drop(ws1);

    let ws2 = Workspace::open_with_options(&tmp, registry(), WorkspaceOpenOptions::default())
        .expect("second open");
    let svc2 = ws2.db().idg_service().expect("idg seeded after reopen");
    assert_eq!(
        svc2.segment_count(),
        segments_1,
        "reload must recover the same segment count"
    );
    assert_eq!(
        svc2.intra_edge_count(),
        edges_1,
        "reload must recover the same intra-edge count"
    );

    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn idg_sidecar_invalidated_on_out_of_band_file_change() {
    // Stress the content-fingerprint check: open the workspace, let
    // it write a sidecar against the original `app.py`, then mutate
    // `app.py` on disk before any in-process invalidation hook can
    // run (the realistic `git checkout` scenario). Reopen — the new
    // workspace's `workspace_content_fingerprint` must reject the
    // stale sidecar so the IDG reflects the new file's symbols, not
    // the old ones.
    let tmp = std::env::temp_dir().join(format!(
        "bonsai-idg-oob-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).expect("create tmp dir");
    write_file(&tmp, "app.py", "def f(x):\n    return x\n");

    let ws1 = Workspace::open_with_options(&tmp, registry(), WorkspaceOpenOptions::default())
        .expect("first open");
    let svc1 = ws1.db().idg_service().expect("idg seeded after first open");
    let edges_1 = svc1.intra_edge_count();
    drop(ws1);

    // Mutate the file out-of-band: add a second function with a call,
    // so a rebuild produces strictly more intra-edges than the
    // pre-mutation IDG.
    write_file(
        &tmp,
        "app.py",
        "def f(x):\n    helper(x)\n\ndef helper(p):\n    sink(p)\n",
    );

    let ws2 = Workspace::open_with_options(&tmp, registry(), WorkspaceOpenOptions::default())
        .expect("second open");
    let svc2 = ws2.db().idg_service().expect("idg seeded after reopen");
    assert!(
        svc2.intra_edge_count() > edges_1,
        "stale sidecar must be rejected; expected edges to grow after file rewrite ({} → {})",
        edges_1,
        svc2.intra_edge_count(),
    );

    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn idg_service_drops_when_workspace_root_invalidated() {
    let tmp = std::env::temp_dir().join(format!(
        "bonsai-idg-drop-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).expect("create tmp dir");
    write_file(&tmp, "a.py", "def g(x):\n    return x\n");

    let ws =
        Workspace::open_with_options(&tmp, registry(), WorkspaceOpenOptions::default()).expect("open ws");
    assert!(ws.db().idg_service().is_some());
    ws.db().invalidate_idg_service();
    assert!(ws.db().idg_service().is_none());
    let svc = ws.build_and_seed_idg_service();
    assert!(svc.segment_count() >= 1);

    let _ = std::fs::remove_dir_all(&tmp);
}
