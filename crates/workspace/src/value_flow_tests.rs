use super::*;
use bonsai_lang_api::{AdapterArc, LanguageRegistry};
use bonsai_taint::ValueFlowNodeKind;
use bonsai_vfs::Vfs;
use std::sync::Arc;

fn build_db_with(files: &[(&str, &str)], adapter: AdapterArc) -> AnalyzerDb {
    let vfs = Arc::new(Vfs::new());
    for (path, source) in files {
        vfs.write((*path).to_string(), Arc::<str>::from(*source));
    }
    let registry = Arc::new(LanguageRegistry::new());
    registry.register(adapter);
    let db = AnalyzerDb::new(vfs, registry);
    for file in db.vfs().all_files() {
        let _ = db.decl_index(file);
    }
    db
}

fn callable_func_ids(db: &AnalyzerDb) -> Vec<FuncId> {
    let global = db.global_index();
    let mut funcs = Vec::new();
    for file in global.all_files() {
        for decl in global.decls_in(file) {
            if matches!(
                decl.kind,
                DeclKind::Function | DeclKind::Method | DeclKind::Constructor
            ) {
                funcs.push(FuncId::new(decl.symbol.raw()));
            }
        }
    }
    funcs.sort_by_key(|func| func.raw());
    funcs
}

#[test]
fn cache_hits_share_arc() {
    let adapter: AdapterArc = Arc::new(bonsai_lang_python::PythonAdapter::new());
    let db = build_db_with(
        &[(
            "a.py",
            "def entry(args):\n    helper(args)\n\ndef helper(p):\n    sink(p)\n",
        )],
        adapter,
    );
    let entry = bonsai_resolve::resolve_callable(&db.global_index(), "entry")
        .into_iter()
        .next()
        .expect("entry resolves");
    let cache = ValueFlowCache::new();
    let g1 = cache.graph_for(entry, &db);
    let g2 = cache.graph_for(entry, &db);
    assert!(Arc::ptr_eq(&g1, &g2), "second hit must reuse Arc");
}

#[test]
fn nodes_matching_finds_param() {
    let adapter: AdapterArc = Arc::new(bonsai_lang_python::PythonAdapter::new());
    let db = build_db_with(
        &[(
            "a.py",
            "def entry(args):\n    helper(args)\n\ndef helper(p):\n    sink(p)\n",
        )],
        adapter,
    );
    let entry = bonsai_resolve::resolve_callable(&db.global_index(), "entry")
        .into_iter()
        .next()
        .expect("entry resolves");
    let cache = ValueFlowCache::new();
    let nodes = cache.nodes_matching(entry, &db, |n| {
        n.kind == ValueFlowNodeKind::Param && n.value_text == "args"
    });
    assert_eq!(nodes.len(), 1, "should find exactly one args param");
}

#[test]
fn sidecar_roundtrip_preserves_graphs() {
    let adapter: AdapterArc = Arc::new(bonsai_lang_python::PythonAdapter::new());
    let db = build_db_with(
        &[(
            "a.py",
            "def entry(args):\n    helper(args)\n\ndef helper(p):\n    sink(p)\n",
        )],
        adapter,
    );
    let entry = bonsai_resolve::resolve_callable(&db.global_index(), "entry")
        .into_iter()
        .next()
        .expect("entry resolves");
    let cache = ValueFlowCache::new();
    let _ = cache.graph_for(entry, &db);
    let initial_len = cache.len();
    assert!(initial_len >= 1, "should have cached at least one graph");

    let tmp = std::env::temp_dir().join(format!("value_flow_test_{}.bin", std::process::id()));
    cache.save_to_disk(&tmp, &db).expect("save to disk succeeds");

    let restored = ValueFlowCache::new();
    let loaded = restored
        .load_from_disk(&tmp, &db)
        .expect("load from disk succeeds");
    assert_eq!(loaded, initial_len, "loaded count must match saved count");

    let _ = std::fs::remove_file(&tmp);
}

#[test]
fn sidecar_rejects_changed_workspace_content() {
    let adapter: AdapterArc = Arc::new(bonsai_lang_python::PythonAdapter::new());
    let original = build_db_with(
        &[("a.py", "def entry(args):\n    return args\n")],
        adapter.clone(),
    );
    let changed = build_db_with(
        &[("a.py", "def entry(args):\n    return sanitize(args)\n")],
        adapter,
    );
    let entry = bonsai_resolve::resolve_callable(&original.global_index(), "entry")
        .into_iter()
        .next()
        .expect("entry resolves");
    let cache = ValueFlowCache::new();
    let _ = cache.graph_for(entry, &original);
    let tmp = std::env::temp_dir().join(format!("value_flow_stale_test_{}.factstore", std::process::id()));
    cache
        .save_to_disk(&tmp, &original)
        .expect("save to disk succeeds");

    let restored = ValueFlowCache::new();
    let loaded = restored
        .load_from_disk(&tmp, &changed)
        .expect("stale sidecar is ignored");
    assert_eq!(loaded, 0, "changed source must reject value-flow sidecar");
    assert!(
        !tmp.exists(),
        "stale value-flow sidecar should be removed after rejection"
    );

    let _ = std::fs::remove_file(&tmp);
}

#[test]
fn prewarm_to_disk_preserves_resident_entries() {
    let adapter: AdapterArc = Arc::new(bonsai_lang_python::PythonAdapter::new());
    let db = build_db_with(
        &[(
            "a.py",
            "def entry(args):\n    return helper(args)\n\n\
                 def helper(p):\n    return sink(p)\n\n\
                 def sink(p):\n    return p\n",
        )],
        adapter,
    );
    let entry = bonsai_resolve::resolve_callable(&db.global_index(), "entry")
        .into_iter()
        .next()
        .expect("entry resolves");
    let expected = callable_func_ids(&db).len();
    let tmp = std::env::temp_dir().join(format!(
        "value_flow_preserve_resident_{}.factstore",
        std::process::id()
    ));
    let cache = ValueFlowCache::new();
    let resident = cache.graph_for(entry, &db);
    assert!(
        !resident.nodes.is_empty(),
        "resident graph must be computed before prewarm"
    );

    let written = cache
        .prewarm_to_disk(&tmp, &db, &InterTaintCaches::default())
        .expect("prewarm to disk succeeds");
    assert_eq!(
        written, expected,
        "prewarm must write resident + newly computed entries"
    );

    let restored = ValueFlowCache::new();
    let loaded = restored.load_from_disk(&tmp, &db).expect("load prewarm sidecar");
    assert_eq!(
        loaded, expected,
        "resident entry must survive sidecar replacement"
    );

    let _ = std::fs::remove_file(&tmp);
}

#[test]
fn save_atomically_replaces_existing_sidecar() {
    // The factstore writer's atomic-rename pattern is exercised
    // by `bonsai_factstore::writer::tests::write_atomic_*`.
    // Here we just verify the workspace-level save_to_disk uses
    // it correctly: writing twice to the same path leaves a
    // single, valid file.
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("v.factstore");
    let cache = ValueFlowCache::new();
    let db = build_db_with(
        &[("a.py", "def entry(args):\n    return args\n")],
        Arc::new(bonsai_lang_python::PythonAdapter::new()),
    );
    cache.save_to_disk(&path, &db).expect("first save");
    assert!(path.exists());
    cache.save_to_disk(&path, &db).expect("second save replaces");
    assert!(path.exists());
}

#[test]
fn load_from_nonexistent_sidecar_returns_zero() {
    let cache = ValueFlowCache::new();
    let db = build_db_with(
        &[("a.py", "def entry(args):\n    return args\n")],
        Arc::new(bonsai_lang_python::PythonAdapter::new()),
    );
    let n = cache
        .load_from_disk(Path::new("/tmp/value_flow_does_not_exist_xyz.bin"), &db)
        .expect("nonexistent path is not an error");
    assert_eq!(n, 0);
}

#[test]
fn forward_closure_via_cache_reaches_callee_param() {
    let adapter: AdapterArc = Arc::new(bonsai_lang_python::PythonAdapter::new());
    let db = build_db_with(
        &[(
            "a.py",
            "def entry(args):\n    helper(args)\n\ndef helper(p):\n    sink(p)\n",
        )],
        adapter,
    );
    let entry = bonsai_resolve::resolve_callable(&db.global_index(), "entry")
        .into_iter()
        .next()
        .expect("entry resolves");
    let cache = ValueFlowCache::new();
    let nodes = cache.nodes_matching(entry, &db, |n| {
        n.kind == ValueFlowNodeKind::Param && n.value_text == "args"
    });
    let origin = nodes.into_iter().next().expect("origin exists");
    let reach = cache.forward_closure(&origin, &db);
    assert!(
        reach.iter().any(|n| n.value_text == "p"),
        "forward closure must reach `p`; got {reach:?}"
    );
}
