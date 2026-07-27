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

struct CountingPythonAdapter {
    declaration_calls: Arc<std::sync::atomic::AtomicUsize>,
    import_calls: Arc<std::sync::atomic::AtomicUsize>,
}

struct ConcurrentPythonAdapter {
    active: Arc<std::sync::atomic::AtomicUsize>,
    max_active: Arc<std::sync::atomic::AtomicUsize>,
    rendezvous: Arc<(parking_lot::Mutex<usize>, parking_lot::Condvar)>,
}

impl LanguageAdapter for CountingPythonAdapter {
    fn language_id(&self) -> LanguageId {
        LanguageId::new("python")
    }

    fn display_name(&self) -> &'static str {
        "Python declaration counter"
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
        self.declaration_calls
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        std::thread::sleep(std::time::Duration::from_millis(100));
        DeclIndex {
            file,
            ..Default::default()
        }
    }

    fn extract_imports(&self, file: FileId, _ctx: &AdapterContext<'_>) -> ImportIndex {
        self.import_calls
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        ImportIndex {
            file,
            imports: Vec::new(),
        }
    }
}

impl LanguageAdapter for ConcurrentPythonAdapter {
    fn language_id(&self) -> LanguageId {
        LanguageId::new("python")
    }

    fn display_name(&self) -> &'static str {
        "Python declaration concurrency recorder"
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
        let active = self.active.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
        self.max_active
            .fetch_max(active, std::sync::atomic::Ordering::SeqCst);

        let (entered, wake) = &*self.rendezvous;
        let mut entered = entered.lock();
        *entered += 1;
        if *entered < 2 {
            wake.wait_for(&mut entered, std::time::Duration::from_secs(1));
        } else {
            wake.notify_all();
        }
        drop(entered);
        self.active.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);

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
fn streaming_syntax_compiler_shares_then_releases_the_canonical_tree() {
    let vfs = Arc::new(Vfs::new());
    let file = vfs.write(
        "fixture.py",
        "import os\n\ndef shared():\n    return os.getcwd()\n",
    );
    let trees = Arc::new(parking_lot::Mutex::new(Vec::new()));
    let registry = Arc::new(LanguageRegistry::new());
    registry.register(Arc::new(RecordingPythonAdapter {
        trees: Arc::clone(&trees),
    }));
    let db = AnalyzerDb::new(vfs, registry);

    let (declarations, imports) = db.syntax_indexes_uncached(file);
    assert!(declarations.is_some());
    assert!(imports.is_some());
    let lowered_tree = {
        let trees = trees.lock();
        assert_eq!(trees.len(), 2);
        assert!(
            Arc::ptr_eq(&trees[0], &trees[1]),
            "declaration and import lowering must consume one exact CST"
        );
        Arc::downgrade(&trees[0])
    };
    drop(declarations);
    drop(imports);
    trees.lock().clear();
    assert!(
        lowered_tree.upgrade().is_none(),
        "one-shot syntax lowering must not retain its Tree-sitter CST"
    );
    assert_eq!(db.stats().cached_decl_indexes, 0);

    let reparsed = db.parse(file).expect("syntax remains available on demand");
    assert!(lowered_tree.upgrade().is_none());
    assert_eq!(
        first_node_text(&reparsed.tree, reparsed.source_text(), "identifier").as_deref(),
        Some("getcwd")
    );
}

#[test]
fn transient_lowering_releases_cst_and_reparses_the_exact_snapshot() {
    let vfs = Arc::new(Vfs::new());
    let file = vfs.write("fixture.py", "def exact():\n    return 1\n");
    let registry = Arc::new(LanguageRegistry::new());
    registry.register(Arc::new(bonsai_lang_python::PythonAdapter::new()));
    let db = AnalyzerDb::new(vfs, registry);

    let parsed = db.parse(file).expect("initial parse");
    let old_tree = Arc::downgrade(&parsed.tree);
    drop(parsed);

    db.decl_index_releasing_syntax(file)
        .expect("lowered declaration IR");
    assert!(
        old_tree.upgrade().is_none(),
        "phase-local Tree-sitter CST must not remain resident after lowering"
    );

    let reparsed = db.parse(file).expect("exact reparse after cache eviction");
    assert_eq!(
        first_node_text(&reparsed.tree, reparsed.source_text(), "identifier").as_deref(),
        Some("exact")
    );
}

#[test]
fn compiler_object_generation_replays_typed_adapter_ir_without_reparsing() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let root = tempfile::tempdir().expect("tempdir");
    let path = root.path().join("fixture.py");
    let vfs = Arc::new(Vfs::new());
    let file = vfs.write(
        path.to_string_lossy().into_owned(),
        "def exact():\n    return 1\n",
    );
    let declaration_calls = Arc::new(AtomicUsize::new(0));
    let import_calls = Arc::new(AtomicUsize::new(0));
    let registry = Arc::new(LanguageRegistry::new());
    registry.register(Arc::new(CountingPythonAdapter {
        declaration_calls: Arc::clone(&declaration_calls),
        import_calls: Arc::clone(&import_calls),
    }));
    let db = AnalyzerDb::new(Arc::clone(&vfs), Arc::clone(&registry));
    db.set_workspace_root(root.path().to_path_buf());

    assert_eq!(
        db.save_compiler_object_sidecar(root.path())
            .expect("save objects"),
        1
    );
    assert_eq!(declaration_calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        db.save_compiler_object_sidecar(root.path())
            .expect("reuse objects"),
        1
    );
    assert_eq!(
        declaration_calls.load(Ordering::SeqCst),
        1,
        "unchanged generations must copy validated object payloads without lowering"
    );

    let reopened = AnalyzerDb::new(Arc::clone(&vfs), registry);
    reopened.set_workspace_root(root.path().to_path_buf());
    let object = reopened
        .compiler_file_object_uncached(file)
        .expect("replay compiler object");
    assert_eq!(object.language.as_deref(), Some("python"));
    assert!(object.declarations.is_some());
    assert!(reopened.import_index_uncached(file).is_some());
    assert_eq!(
        declaration_calls.load(Ordering::SeqCst),
        1,
        "an exact compiler-object hit must not invoke the language adapter again"
    );
    assert_eq!(
        import_calls.load(Ordering::SeqCst),
        1,
        "streaming imports must reuse exact compiler-object IR without invoking the adapter again"
    );

    vfs.write(
        path.to_string_lossy().into_owned(),
        "def changed():\n    return 2\n",
    );
    assert_eq!(
        reopened
            .save_compiler_object_sidecar(root.path())
            .expect("replace changed object"),
        1
    );
    assert_eq!(
        declaration_calls.load(Ordering::SeqCst),
        2,
        "a changed digest must lower exactly that compiler object again"
    );
}

#[test]
fn scoped_compiler_object_session_reuses_ir_without_publishing_a_partial_sidecar() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let root = tempfile::tempdir().expect("tempdir");
    let first_path = root.path().join("first.py");
    let second_path = root.path().join("second.py");
    let vfs = Arc::new(Vfs::new());
    let first = vfs.write(
        first_path.to_string_lossy().into_owned(),
        "def first():\n    return 1\n",
    );
    let second = vfs.write(
        second_path.to_string_lossy().into_owned(),
        "def second():\n    return 2\n",
    );
    let declaration_calls = Arc::new(AtomicUsize::new(0));
    let import_calls = Arc::new(AtomicUsize::new(0));
    let registry = Arc::new(LanguageRegistry::new());
    registry.register(Arc::new(CountingPythonAdapter {
        declaration_calls: Arc::clone(&declaration_calls),
        import_calls: Arc::clone(&import_calls),
    }));
    let db = AnalyzerDb::new(Arc::clone(&vfs), registry);
    db.set_workspace_root(root.path().to_path_buf());

    assert_eq!(
        db.ensure_compiler_object_session(&[second, first, second])
            .expect("build scoped compiler session"),
        2
    );
    assert_eq!(declaration_calls.load(Ordering::SeqCst), 2);
    assert_eq!(import_calls.load(Ordering::SeqCst), 2);
    assert!(
        !compiler_object_sidecar_path(root.path()).exists(),
        "a scoped query must not publish a partial compiler generation under the workspace"
    );

    assert_eq!(
        db.ensure_compiler_object_session(&[first, second])
            .expect("reuse scoped compiler session"),
        0
    );
    assert!(db.compiler_file_object_uncached(first).is_some());
    assert!(db.compiler_file_object_uncached(second).is_some());
    assert_eq!(
        declaration_calls.load(Ordering::SeqCst),
        2,
        "repeated compiler phases must stream exact scoped objects without reparsing"
    );

    vfs.write(
        second_path.to_string_lossy().into_owned(),
        "def changed():\n    return 3\n",
    );
    db.ensure_compiler_object_session(&[first, second])
        .expect("replace changed scoped object");
    assert_eq!(
        declaration_calls.load(Ordering::SeqCst),
        3,
        "only the compiler object whose strong source digest changed may be lowered again"
    );
}

#[test]
fn compiler_object_generation_preserves_parser_diagnostics() {
    let root = tempfile::tempdir().expect("tempdir");
    let path = root.path().join("broken.py");
    let vfs = Arc::new(Vfs::new());
    let file = vfs.write(path.to_string_lossy().into_owned(), "def broken(\n");
    let registry = Arc::new(LanguageRegistry::new());
    registry.register(Arc::new(bonsai_lang_python::PythonAdapter::new()));
    let db = AnalyzerDb::new(Arc::clone(&vfs), Arc::clone(&registry));
    db.set_workspace_root(root.path().to_path_buf());
    db.save_compiler_object_sidecar(root.path())
        .expect("save objects");

    let reopened = AnalyzerDb::new(vfs, registry);
    reopened.set_workspace_root(root.path().to_path_buf());
    let object = reopened
        .compiler_file_object_uncached(file)
        .expect("replay compiler object");
    assert!(
        object
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code.as_deref() == Some("syntax-error")),
        "warm compiler objects must preserve exhaustive Tree-sitter diagnostics"
    );
    assert!(
        reopened
            .diagnostics()
            .iter()
            .any(|diagnostic| diagnostic.code.as_deref() == Some("syntax-error")),
        "object diagnostics must publish through the ordinary database facade"
    );
}

#[test]
fn compiler_object_invalidation_removes_stale_diagnostics() {
    let vfs = Arc::new(Vfs::new());
    let file = vfs.write("broken.py", "def broken(\n");
    let registry = Arc::new(LanguageRegistry::new());
    registry.register(Arc::new(bonsai_lang_python::PythonAdapter::new()));
    let db = AnalyzerDb::new(Arc::clone(&vfs), registry);

    let _ = db.compiler_file_object_uncached(file);
    assert!(db.diagnostics().iter().any(|diagnostic| {
        diagnostic.span.file == file && diagnostic.code.as_deref() == Some("syntax-error")
    }));

    vfs.write("broken.py", "def repaired():\n    return 1\n");
    db.invalidate_file(file);
    let _ = db.compiler_file_object_uncached(file);
    assert!(
        db.diagnostics().iter().all(|diagnostic| {
            diagnostic.span.file != file || diagnostic.code.as_deref() != Some("syntax-error")
        }),
        "diagnostics from an older source version must not survive invalidation"
    );
}

#[test]
fn global_index_concurrent_callers_lower_each_file_once() {
    use std::sync::{atomic::AtomicUsize, Barrier};

    let vfs = Arc::new(Vfs::new());
    vfs.write("fixture.py", "def shared():\n    return 1\n");
    let declaration_calls = Arc::new(AtomicUsize::new(0));
    let import_calls = Arc::new(AtomicUsize::new(0));
    let registry = Arc::new(LanguageRegistry::new());
    registry.register(Arc::new(CountingPythonAdapter {
        declaration_calls: Arc::clone(&declaration_calls),
        import_calls,
    }));
    let db = AnalyzerDb::new(vfs, registry);
    let start = Arc::new(Barrier::new(3));

    let callers: Vec<_> = (0..2)
        .map(|_| {
            let db = db.clone();
            let start = Arc::clone(&start);
            std::thread::spawn(move || {
                start.wait();
                db.global_index()
            })
        })
        .collect();
    start.wait();
    let mut indexes = callers
        .into_iter()
        .map(|caller| caller.join().expect("global-index caller"));
    let left = indexes.next().expect("first global index");
    let right = indexes.next().expect("second global index");

    assert_eq!(
        declaration_calls.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "parallel callers must share one workspace lowering pass"
    );
    assert!(Arc::ptr_eq(&left, &right));
}

#[test]
fn global_index_lowering_does_not_hold_the_decl_cache_lock() {
    let vfs = Arc::new(Vfs::new());
    vfs.write("left.py", "def left():\n    return 1\n");
    vfs.write("right.py", "def right():\n    return 2\n");
    let active = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let max_active = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let registry = Arc::new(LanguageRegistry::new());
    registry.register(Arc::new(ConcurrentPythonAdapter {
        active,
        max_active: Arc::clone(&max_active),
        rendezvous: Arc::new((parking_lot::Mutex::new(0), parking_lot::Condvar::new())),
    }));
    let db = AnalyzerDb::new(Arc::clone(&vfs), registry);
    let files = vfs.all_files();
    let mut global = GlobalIndex::new();

    db.populate_global_index_consuming_with_workers(&mut global, &files, 2);

    assert_eq!(global.all_files().count(), 2);
    assert_eq!(
        max_active.load(std::sync::atomic::Ordering::SeqCst),
        2,
        "per-file AST lowering must run outside the declaration-cache write lock"
    );
}

#[test]
fn global_index_single_flight_is_safe_from_parallel_rayon_callers() {
    use std::sync::{atomic::AtomicUsize, Barrier};

    let vfs = Arc::new(Vfs::new());
    vfs.write("fixture.py", "def shared():\n    return 1\n");
    let declaration_calls = Arc::new(AtomicUsize::new(0));
    let import_calls = Arc::new(AtomicUsize::new(0));
    let registry = Arc::new(LanguageRegistry::new());
    registry.register(Arc::new(CountingPythonAdapter {
        declaration_calls: Arc::clone(&declaration_calls),
        import_calls,
    }));
    let db = AnalyzerDb::new(vfs, registry);
    let start = Barrier::new(2);
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(2)
        .build()
        .expect("caller pool");

    let (left, right) = pool.install(|| {
        rayon::join(
            || {
                start.wait();
                db.global_index()
            },
            || {
                start.wait();
                db.global_index()
            },
        )
    });

    assert_eq!(
        declaration_calls.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "Rayon callers must share one workspace lowering pass"
    );
    assert!(Arc::ptr_eq(&left, &right));
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
