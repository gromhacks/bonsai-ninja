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
fn structural_flow_ids_distinguish_same_named_declarations() {
    let adapter: AdapterArc = Arc::new(bonsai_lang_python::PythonAdapter::new());
    let db = build_db_with(
        &[
            ("a.py", "def run():\n    return 1\n"),
            ("b.py", "def run():\n    return 2\n"),
        ],
        adapter,
    );
    let global = db.global_index();
    let mut runs = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .filter(|decl| decl.name == "run")
        .map(|decl| FuncId::new(decl.symbol.raw()))
        .collect::<Vec<_>>();
    runs.sort_by_key(|func| func.raw());
    assert_eq!(runs.len(), 2);

    let first = compute_structural_flow_id(global.as_ref(), &db, db.vfs(), &[runs[0]]);
    let second = compute_structural_flow_id(global.as_ref(), &db, db.vfs(), &[runs[1]]);
    assert_ne!(
        first, second,
        "same display names in different compiler declarations need distinct stable ids"
    );
    assert_eq!(
        first,
        compute_structural_flow_id(global.as_ref(), &db, db.vfs(), &[runs[0]]),
        "the same exact compiler path must hash deterministically"
    );
}

#[test]
fn resident_id_release_preserves_exact_recomputation() {
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
    let before = cache.id_for_func(sink, &db, db.vfs());
    assert!(cache.cached_id(sink).is_some());

    cache.release_resident_ids();
    assert!(
        cache.cached_id(sink).is_none(),
        "phase release must drop only resident presentation rows"
    );

    let after = cache.id_for_func(sink, &db, db.vfs());
    assert_eq!(
        before, after,
        "released ids must recompute deterministically from compiler facts"
    );
}

#[test]
fn symbol_summary_id_is_constant_size_under_fan_in() {
    let adapter: AdapterArc = Arc::new(bonsai_lang_python::PythonAdapter::new());
    let mut source = String::new();
    for idx in 0..40 {
        source.push_str(&format!("def entry_{idx}():\n    return sink()\n\n"));
    }
    source.push_str("def sink():\n    return 1\n");
    let db = build_db_with(&[("a.py", source.as_str())], adapter);
    let sink = func_id_by_name(&db, "sink");
    let cache = FlowIdCache::new();

    let id = cache.id_for_func(sink, &db, db.vfs());
    assert!(id.starts_with("F:"));
    assert_eq!(id.len(), 18, "fan-in changes graph degree, not symbol-id size");
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
    crate::cache_fingerprint::register_workspace_cache_root(&root).expect("bind workspace cache");
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
    let resident = cache.id_for_func(entry, &db, db.vfs());
    assert!(
        !resident.is_empty(),
        "resident id must be computed before prewarm"
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
    assert_eq!(restored.id_for_func(entry, &db, db.vfs()), resident);

    let _ = std::fs::remove_file(&tmp);
}
