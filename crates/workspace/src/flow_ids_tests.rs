use super::*;
use bonsai_lang_api::{AdapterArc, LanguageRegistry};
use bonsai_vfs::Vfs;
use std::path::PathBuf;
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

fn tempdir_for_test(name: &str) -> PathBuf {
    let base = std::env::temp_dir();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
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

fn func_id_by_name(db: &AnalyzerDb, name: &str) -> FuncId {
    let global = db.global_index();
    for file in global.all_files() {
        for decl in global.decls_in(file) {
            if decl.name == name {
                return FuncId::new(decl.symbol.raw());
            }
        }
    }
    panic!("missing function {name}");
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
fn batch_labels_match_scalar_labels() {
    let adapter: AdapterArc = Arc::new(bonsai_lang_python::PythonAdapter::new());
    let db = build_db_with(
        &[(
            "a.py",
            "def entry(request):\n    return middle(request)\n\n\
                 def middle(value):\n    return sink(value)\n\n\
                 def sink(value):\n    return value\n",
        )],
        adapter,
    );
    let funcs = [
        func_id_by_name(&db, "entry"),
        func_id_by_name(&db, "middle"),
        func_id_by_name(&db, "sink"),
    ];

    let scalar_cache = FlowIdCache::new();
    let batch_cache = FlowIdCache::new();
    let batch: AHashMap<FuncId, (Arc<[String]>, bool)> = batch_cache
        .labels_for_funcs(&funcs, &db, db.vfs())
        .into_iter()
        .map(|(func, labels, truncated)| (func, (labels, truncated)))
        .collect();
    let precomputed_cache = FlowIdCache::new();
    let cg = precomputed_cache.call_graph(&db, db.vfs());
    let chain_sets: Vec<(FuncId, Vec<Vec<FuncId>>, bool)> = funcs
        .iter()
        .map(|&func| {
            let (chains, truncated) = enumerate_chains(&cg, func, MAX_CHAINS, MAX_PROBES);
            (func, chains, truncated)
        })
        .collect();
    let precomputed: AHashMap<FuncId, (Arc<[String]>, bool)> = precomputed_cache
        .labels_for_chain_sets_with_options(chain_sets, &db, db.vfs(), FlowIdLabelOptions::default())
        .into_iter()
        .map(|(func, labels, truncated)| (func, (labels, truncated)))
        .collect();

    for func in funcs {
        let scalar_labels = scalar_cache.labels_for_func(func, &db, db.vfs());
        let scalar_truncated = scalar_cache.was_truncated(func);
        let (batch_labels, batch_truncated) = batch
            .get(&func)
            .unwrap_or_else(|| panic!("missing batch labels for {:?}", func));
        let (precomputed_labels, precomputed_truncated) = precomputed
            .get(&func)
            .unwrap_or_else(|| panic!("missing precomputed labels for {:?}", func));
        assert_eq!(&scalar_labels, batch_labels);
        assert_eq!(scalar_truncated, *batch_truncated);
        assert_eq!(&scalar_labels, precomputed_labels);
        assert_eq!(scalar_truncated, *precomputed_truncated);
    }
}

#[test]
fn resident_label_release_preserves_exact_recomputation() {
    let adapter: AdapterArc = Arc::new(bonsai_lang_python::PythonAdapter::new());
    let db = build_db_with(
        &[(
            "a.py",
            "def entry(value):\n    return sink(value)\n\n\
             def sink(value):\n    return value\n",
        )],
        adapter,
    );
    let sink = func_id_by_name(&db, "sink");
    let cache = FlowIdCache::new();
    let before = cache.labels_for_func(sink, &db, db.vfs());
    assert!(cache.cached_line(sink).is_some());

    cache.release_resident_labels();
    assert!(
        cache.cached_line(sink).is_none(),
        "phase release must drop only resident presentation rows"
    );

    let after = cache.labels_for_func(sink, &db, db.vfs());
    assert_eq!(
        before, after,
        "released labels must recompute deterministically from compiler facts"
    );
}

#[test]
fn exact_label_options_lift_default_label_caps() {
    let adapter: AdapterArc = Arc::new(bonsai_lang_python::PythonAdapter::new());
    let mut source = String::new();
    for idx in 0..40 {
        source.push_str(&format!("def entry_{idx}():\n    return sink()\n\n"));
    }
    source.push_str("def sink():\n    return 1\n");
    let db = build_db_with(&[("a.py", source.as_str())], adapter);
    let sink = func_id_by_name(&db, "sink");
    let cache = FlowIdCache::new();

    let default = cache.labels_for_funcs(&[sink], &db, db.vfs());
    let (_, default_labels, default_truncated) = default.into_iter().next().expect("default sink labels");
    assert!(
        default_truncated,
        "default labels must expose truncation when the label cap is hit"
    );
    assert_eq!(
        default_labels.len(),
        MAX_LABELS_PER_FUNC,
        "default labels stay bounded for browse cells"
    );

    let exact = cache.labels_for_funcs_with_options(&[sink], &db, db.vfs(), FlowIdLabelOptions::exhaustive());
    let (_, exact_labels, exact_truncated) = exact.into_iter().next().expect("exact sink labels");
    assert!(
        !exact_truncated,
        "exhaustive labels must not reuse the bounded cached truncation state"
    );
    assert_eq!(
        exact_labels.len(),
        40,
        "exhaustive labels must enumerate every fan-in flow id"
    );
}

#[test]
fn sidecar_rejects_changed_workspace_content() {
    let adapter: AdapterArc = Arc::new(bonsai_lang_python::PythonAdapter::new());
    let original = build_db_with(
        &[(
            "a.py",
            "def entry():\n    return sink()\n\ndef sink():\n    return 1\n",
        )],
        adapter.clone(),
    );
    let changed = build_db_with(
        &[(
            "a.py",
            "def entry():\n    return 1\n\ndef sink():\n    return 1\n",
        )],
        adapter,
    );
    let tmp = std::env::temp_dir().join(format!("flow_ids_stale_test_{}.factstore", std::process::id()));
    let cache = FlowIdCache::new();
    cache
        .prewarm_to_disk(&tmp, &original, original.vfs(), |_| {})
        .expect("prewarm to disk succeeds");

    let restored = FlowIdCache::new();
    let loaded = restored
        .load_from_disk(&tmp, &changed)
        .expect("stale sidecar is ignored");
    assert_eq!(loaded, 0, "changed source must reject flow-id sidecar");
    assert!(
        !tmp.exists(),
        "stale flow-id sidecar should be removed after rejection"
    );

    let _ = std::fs::remove_file(&tmp);
}

#[test]
fn sidecar_file_validator_rejects_corrupt_payload_even_when_size_matches() {
    let tmp = std::env::temp_dir().join(format!(
        "flow_ids_corrupt_validator_{}.factstore",
        std::process::id()
    ));
    let writer = FactStoreWriter::create(&tmp, FLOW_IDS_TABLE_ID, 42).expect("create flow-id factstore");
    writer
        .add(7, 11, b"flow-id payload")
        .expect("write factstore row");
    let entries = writer.finish().expect("finish flow-id factstore");
    assert_eq!(entries, 1);
    assert_eq!(
        FlowIdCache::validate_sidecar_file(&tmp).expect("validate fresh flow-id factstore"),
        1
    );

    let bytes = std::fs::metadata(&tmp).expect("flow-id metadata").len();
    std::fs::write(&tmp, vec![0_u8; bytes as usize]).expect("overwrite same-size corrupt factstore");
    assert!(
        FlowIdCache::validate_sidecar_file(&tmp).is_err(),
        "same-size corrupt flow-id factstore must not validate"
    );

    let _ = std::fs::remove_file(&tmp);
}

#[test]
fn sidecar_rejects_changed_dependency_metadata() {
    let adapter: AdapterArc = Arc::new(bonsai_lang_python::PythonAdapter::new());
    let db = build_db_with(
        &[(
            "a.py",
            "def entry():\n    return sink()\n\ndef sink():\n    return 1\n",
        )],
        adapter.clone(),
    );
    let root = tempdir_for_test("flow-ids-sidecar-deps");
    std::fs::create_dir(root.join(".bonsai")).expect("create .bonsai");
    std::fs::write(root.join("pyproject.toml"), "[project]\nname = \"demo\"\n").expect("write pyproject");
    let path = FlowIdCache::sidecar_path(&root);

    let cache = FlowIdCache::new();
    cache
        .prewarm_to_disk(&path, &db, db.vfs(), |_| {})
        .expect("prewarm to disk succeeds");
    assert!(path.exists(), "prewarm should write flow-id sidecar");

    let fresh = FlowIdCache::new();
    let fresh_loaded = fresh.load_from_disk(&path, &db).expect("load fresh sidecar");
    assert!(
        fresh_loaded > 0,
        "unchanged dependency metadata should allow flow-id sidecar reuse"
    );

    std::fs::write(
        root.join("pyproject.toml"),
        "[project]\nname = \"demo\"\ndependencies = [\"flask\"]\n",
    )
    .expect("rewrite pyproject");

    let changed = build_db_with(
        &[(
            "a.py",
            "def entry():\n    return sink()\n\ndef sink():\n    return 1\n",
        )],
        adapter,
    );
    let restored = FlowIdCache::new();
    let loaded = restored
        .load_from_disk(&path, &changed)
        .expect("changed metadata sidecar is ignored");
    assert_eq!(
        loaded, 0,
        "dependency metadata changes must reject flow-id sidecar"
    );
    assert!(
        !path.exists(),
        "stale flow-id sidecar should be removed after dependency metadata rejection"
    );

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn prewarm_to_disk_preserves_resident_entries() {
    let adapter: AdapterArc = Arc::new(bonsai_lang_python::PythonAdapter::new());
    let db = build_db_with(
        &[(
            "a.py",
            "def entry(arg):\n    return helper(arg)\n\n\
                 def helper(value):\n    return sink(value)\n\n\
                 def sink(value):\n    return value\n",
        )],
        adapter,
    );
    let entry = func_id_by_name(&db, "entry");
    let expected = callable_func_ids(&db).len();
    let tmp = std::env::temp_dir().join(format!(
        "flow_ids_preserve_resident_{}.factstore",
        std::process::id()
    ));
    let cache = FlowIdCache::new();
    let resident = cache.labels_for_func(entry, &db, db.vfs());
    assert!(
        !resident.is_empty(),
        "resident line must be computed before prewarm"
    );

    let written = cache
        .prewarm_to_disk(&tmp, &db, db.vfs(), |_| {})
        .expect("prewarm to disk succeeds");
    assert_eq!(
        written, expected,
        "prewarm must write resident + newly computed entries"
    );

    let restored = FlowIdCache::new();
    let loaded = restored.load_from_disk(&tmp, &db).expect("load prewarm sidecar");
    assert_eq!(
        loaded, expected,
        "resident entry must survive sidecar replacement"
    );
    assert_eq!(restored.labels_for_func(entry, &db, db.vfs()), resident);

    let _ = std::fs::remove_file(&tmp);
}
