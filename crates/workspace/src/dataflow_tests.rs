use super::{DataFlowCache, DATAFLOW_FACTSTORE_TABLE_ID};
use bonsai_common::FuncId;
use bonsai_db::AnalyzerDb;
use bonsai_lang_api::{AdapterArc, DeclKind, LanguageRegistry};
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
fn factstore_sidecar_file_validator_rejects_corrupt_payload_even_when_size_matches() {
    let tmp = std::env::temp_dir().join(format!(
        "dataflow_corrupt_validator_{}.factstore",
        std::process::id()
    ));
    let writer = bonsai_factstore::FactStoreWriter::create(&tmp, DATAFLOW_FACTSTORE_TABLE_ID, 42)
        .expect("create dataflow factstore");
    writer
        .add(7, 11, b"dataflow payload")
        .expect("write factstore row");
    let entries = writer.finish().expect("finish dataflow factstore");
    assert_eq!(entries, 1);
    assert_eq!(
        DataFlowCache::validate_factstore_sidecar_file(&tmp).expect("validate fresh dataflow factstore"),
        1
    );

    let bytes = std::fs::metadata(&tmp).expect("dataflow metadata").len();
    std::fs::write(&tmp, vec![0_u8; bytes as usize]).expect("overwrite same-size corrupt factstore");
    assert!(
        DataFlowCache::validate_factstore_sidecar_file(&tmp).is_err(),
        "same-size corrupt dataflow factstore must not validate"
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
    let entry = func_id_by_name(&db, "entry");
    let expected = callable_func_ids(&db).len();
    let tmp = std::env::temp_dir().join(format!(
        "dataflow_preserve_resident_{}.factstore",
        std::process::id()
    ));
    let cache = DataFlowCache::new();
    let resident = cache.facts_for(entry, &db);
    assert!(
        !resident.by_kind.is_empty(),
        "resident dataflow facts must be computed before prewarm"
    );

    let written = cache
        .prewarm_to_disk(&tmp, &db, |_| {})
        .expect("prewarm to disk succeeds");
    assert_eq!(
        written, expected,
        "prewarm must write resident + newly computed entries"
    );

    let restored = DataFlowCache::new();
    let loaded = restored
        .load_factstore_sidecar(&tmp, &db)
        .expect("load prewarm sidecar");
    assert_eq!(
        loaded, expected,
        "resident entry must survive sidecar replacement"
    );

    let _ = std::fs::remove_file(&tmp);
}

#[test]
fn factstore_sidecar_rejects_changed_workspace_content() {
    let adapter: AdapterArc = Arc::new(bonsai_lang_python::PythonAdapter::new());
    let original = build_db_with(
        &[("a.py", "def entry(args):\n    return args\n")],
        adapter.clone(),
    );
    let changed = build_db_with(
        &[("a.py", "def entry(args):\n    return sanitize(args)\n")],
        adapter,
    );
    let tmp = std::env::temp_dir().join(format!(
        "dataflow_stale_factstore_test_{}.factstore",
        std::process::id()
    ));
    let cache = DataFlowCache::new();
    cache
        .prewarm_to_disk(&tmp, &original, |_| {})
        .expect("prewarm to disk succeeds");

    let restored = DataFlowCache::new();
    let loaded = restored
        .load_factstore_sidecar(&tmp, &changed)
        .expect("stale sidecar is ignored");
    assert_eq!(loaded, 0, "changed source must reject dataflow sidecar");
    assert!(
        !tmp.exists(),
        "stale dataflow sidecar should be removed after rejection"
    );

    let _ = std::fs::remove_file(&tmp);
}
