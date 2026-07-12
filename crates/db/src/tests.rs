use super::*;
use bonsai_lang_api::{AdapterError, LanguageAdapter, LanguageId};
use bonsai_vfs::Vfs;

struct EmptyImportPythonAdapter;

impl LanguageAdapter for EmptyImportPythonAdapter {
    fn language_id(&self) -> LanguageId {
        LanguageId::new("python")
    }

    fn display_name(&self) -> &'static str {
        "Python with empty import index"
    }

    fn file_extensions(&self) -> &'static [&'static str] {
        &["py"]
    }

    fn tree_sitter_language(&self) -> Result<tree_sitter::Language, AdapterError> {
        bonsai_lang_python::PythonAdapter::new().tree_sitter_language()
    }

    fn capabilities(&self) -> bonsai_lang_api::LanguageCapabilities {
        bonsai_lang_api::LanguageCapabilities::unsupported()
    }

    fn extract_declarations(&self, file: FileId, _ctx: &AdapterContext<'_>) -> DeclIndex {
        DeclIndex {
            file,
            ..Default::default()
        }
    }

    fn extract_imports(&self, file: FileId, _ctx: &AdapterContext<'_>) -> ImportIndex {
        ImportIndex {
            file,
            imports: Vec::new(),
        }
    }
}

struct RecordingPythonAdapter {
    trees: Arc<parking_lot::Mutex<Vec<Arc<bonsai_lang_api::SyntaxTree>>>>,
}

impl RecordingPythonAdapter {
    fn record_tree(&self, file: FileId, ctx: &AdapterContext<'_>) {
        if let Some((_, tree)) = bonsai_lang_api::kit::parse_with("python", file, ctx) {
            self.trees.lock().push(tree);
        }
    }
}

impl LanguageAdapter for RecordingPythonAdapter {
    fn language_id(&self) -> LanguageId {
        LanguageId::new("python")
    }

    fn display_name(&self) -> &'static str {
        "Python tree recorder"
    }

    fn file_extensions(&self) -> &'static [&'static str] {
        &["py"]
    }

    fn tree_sitter_language(&self) -> Result<tree_sitter::Language, AdapterError> {
        bonsai_lang_python::PythonAdapter::new().tree_sitter_language()
    }

    fn capabilities(&self) -> bonsai_lang_api::LanguageCapabilities {
        bonsai_lang_api::LanguageCapabilities::unsupported()
    }

    fn extract_declarations(&self, file: FileId, ctx: &AdapterContext<'_>) -> DeclIndex {
        self.record_tree(file, ctx);
        DeclIndex {
            file,
            ..Default::default()
        }
    }

    fn extract_imports(&self, file: FileId, ctx: &AdapterContext<'_>) -> ImportIndex {
        self.record_tree(file, ctx);
        ImportIndex {
            file,
            imports: Vec::new(),
        }
    }
}

#[test]
fn imports_for_treats_empty_adapter_index_as_authoritative() {
    let vfs = Arc::new(Vfs::new());
    let file = vfs.write(
        "fixture.py",
        Arc::<str>::from("import os\n\ndef handler():\n    return os.getcwd()\n"),
    );
    let registry = Arc::new(LanguageRegistry::new());
    registry.register(Arc::new(EmptyImportPythonAdapter));
    let db = AnalyzerDb::new(vfs, registry);

    assert!(
        db.imports_for(file).is_empty(),
        "adapter-returned empty imports must not fall through to generic syntax extraction"
    );
}

#[test]
fn declaration_and_import_adapter_passes_share_the_canonical_tree_arc() {
    let vfs = Arc::new(Vfs::new());
    let file = vfs.write("fixture.py", "def shared():\n    return 1\n");
    let trees = Arc::new(parking_lot::Mutex::new(Vec::new()));
    let registry = Arc::new(LanguageRegistry::new());
    registry.register(Arc::new(RecordingPythonAdapter {
        trees: Arc::clone(&trees),
    }));
    let db = AnalyzerDb::new(vfs, registry);

    db.decl_index(file).expect("declaration pass");
    db.import_index(file).expect("import pass");
    let parsed = db.parse(file).expect("canonical parse");

    let trees = trees.lock();
    assert_eq!(trees.len(), 2);
    assert!(Arc::ptr_eq(&trees[0], &trees[1]));
    assert!(Arc::ptr_eq(&trees[0], &parsed.tree));
}

#[test]
fn tree_provider_honors_the_requested_snapshot_after_a_concurrent_write() {
    let vfs = Arc::new(Vfs::new());
    let file = vfs.write("fixture.py", "def before():\n    return 1\n");
    let before_snapshot = vfs.snapshot(file).expect("before snapshot");
    let registry = Arc::new(LanguageRegistry::new());
    registry.register(Arc::new(EmptyImportPythonAdapter));
    let db = AnalyzerDb::new(Arc::clone(&vfs), registry);

    vfs.write("fixture.py", "def after():\n    return 2\n");
    let before_tree = bonsai_lang_api::TreeProvider::tree_for_snapshot(&db, "python", &before_snapshot)
        .expect("tree for retained snapshot");
    let current = db.parse(file).expect("current parse");

    assert_eq!(
        first_node_text(&before_tree, &before_snapshot.text, "identifier").as_deref(),
        Some("before")
    );
    assert_eq!(
        first_node_text(&current.tree, current.source_text(), "identifier").as_deref(),
        Some("after")
    );
    assert!(!Arc::ptr_eq(&before_tree, &current.tree));
}

#[test]
fn configured_idg_services_are_isolated_by_semantic_fingerprint() {
    let db = AnalyzerDb::new(Arc::new(Vfs::new()), Arc::new(LanguageRegistry::new()));
    let service = || {
        Arc::new(bonsai_idg::IdgQueryService::new(
            Arc::new(bonsai_idg::IdgWorkspace::new()),
            Arc::new(bonsai_index::GlobalIndex::new()),
        ))
    };
    let first = service();
    let second = service();

    let cached_first = db.set_idg_service_for_semantics(11, first.clone());
    let cached_second = db.set_idg_service_for_semantics(22, second.clone());
    assert!(Arc::ptr_eq(&cached_first, &first));
    assert!(Arc::ptr_eq(&cached_second, &second));
    assert!(Arc::ptr_eq(
        &db.idg_service_for_semantics(11).expect("first semantics"),
        &first
    ));
    assert!(Arc::ptr_eq(&db.set_idg_service_for_semantics(11, second), &first));

    db.invalidate_idg_service();
    assert!(db.idg_service_for_semantics(11).is_none());
    assert!(db.idg_service_for_semantics(22).is_none());
}

#[test]
fn configured_idg_initialization_is_single_flight_per_fingerprint() {
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        mpsc, Condvar, Mutex as StdMutex,
    };
    use std::time::Duration;

    let db = AnalyzerDb::new(Arc::new(Vfs::new()), Arc::new(LanguageRegistry::new()));
    let init_count = Arc::new(AtomicUsize::new(0));
    let release = Arc::new((StdMutex::new(false), Condvar::new()));
    let (first_init_tx, first_init_rx) = mpsc::channel();

    let first_db = db.clone();
    let first_count = Arc::clone(&init_count);
    let first_release = Arc::clone(&release);
    let first = std::thread::spawn(move || {
        first_db.get_or_init_idg_service_for_semantics(77, || {
            first_count.fetch_add(1, Ordering::SeqCst);
            first_init_tx.send(()).expect("announce first initializer");
            let (lock, wake) = &*first_release;
            let mut released = lock.lock().expect("single-flight release lock");
            while !*released {
                released = wake.wait(released).expect("single-flight release wait");
            }
            empty_idg_service()
        })
    });

    first_init_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("first initializer starts");

    let second_db = db.clone();
    let second_count = Arc::clone(&init_count);
    let (second_attempt_tx, second_attempt_rx) = mpsc::channel();
    let (duplicate_init_tx, duplicate_init_rx) = mpsc::channel();
    let second = std::thread::spawn(move || {
        second_attempt_tx.send(()).expect("announce second caller");
        second_db.get_or_init_idg_service_for_semantics(77, || {
            second_count.fetch_add(1, Ordering::SeqCst);
            duplicate_init_tx
                .send(())
                .expect("announce duplicate initializer");
            empty_idg_service()
        })
    });
    second_attempt_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("second caller attempts initialization");
    let duplicate_started = duplicate_init_rx.recv_timeout(Duration::from_millis(200));

    {
        let (lock, wake) = &*release;
        *lock.lock().expect("single-flight release lock") = true;
        wake.notify_all();
    }
    let first_service = first.join().expect("first initializer thread");
    let second_service = second.join().expect("second initializer thread");

    assert!(
        duplicate_started.is_err(),
        "same-fingerprint peer ran a duplicate initializer"
    );
    assert_eq!(init_count.load(Ordering::SeqCst), 1);
    assert!(Arc::ptr_eq(&first_service, &second_service));
    assert!(Arc::ptr_eq(
        &db.idg_service_for_semantics(77).expect("initialized service"),
        &first_service
    ));
}

fn empty_idg_service() -> Arc<bonsai_idg::IdgQueryService> {
    Arc::new(bonsai_idg::IdgQueryService::new(
        Arc::new(bonsai_idg::IdgWorkspace::new()),
        Arc::new(bonsai_index::GlobalIndex::new()),
    ))
}

fn first_node_text(tree: &tree_sitter::Tree, source: &str, kind: &str) -> Option<String> {
    let mut stack = vec![tree.root_node()];
    while let Some(node) = stack.pop() {
        if node.kind() == kind {
            return source.get(node.byte_range()).map(ToOwned::to_owned);
        }
        let mut cursor = node.walk();
        stack.extend(node.named_children(&mut cursor));
    }
    None
}
