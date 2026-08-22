use super::*;
use bonsai_lang_api::{AdapterContext, DeclIndex, ImportIndex, LanguageAdapter, LanguageCapabilities};

struct TestPythonAdapter;

struct TestCAdapter;

impl LanguageAdapter for TestPythonAdapter {
    fn language_id(&self) -> LanguageId {
        LanguageId::new("python")
    }

    fn display_name(&self) -> &'static str {
        "test python"
    }

    fn file_extensions(&self) -> &'static [&'static str] {
        &["py"]
    }

    fn tree_sitter_language(&self) -> Result<tree_sitter::Language, AdapterError> {
        bonsai_lang_api::kit::language_from_pack("python")
    }

    fn parse_normalization_edits(
        &self,
        snapshot: &bonsai_lang_api::FileSnapshot,
        _vfs: &Vfs,
    ) -> Vec<bonsai_lang_api::ParseRecoveryEdit> {
        (snapshot.path.file_name().and_then(|name| name.to_str()) == Some("template.py"))
            .then(|| bonsai_lang_api::ParseRecoveryEdit::new(0, 6))
            .into_iter()
            .collect()
    }

    fn capabilities(&self) -> LanguageCapabilities {
        LanguageCapabilities::unsupported()
    }

    fn extract_declarations(&self, file: FileId, _ctx: &AdapterContext<'_>) -> DeclIndex {
        DeclIndex {
            file,
            ..DeclIndex::default()
        }
    }

    fn extract_imports(&self, file: FileId, _ctx: &AdapterContext<'_>) -> ImportIndex {
        ImportIndex {
            file,
            imports: Vec::new(),
        }
    }
}

fn test_python_adapter() -> AdapterArc {
    Arc::new(TestPythonAdapter)
}

impl LanguageAdapter for TestCAdapter {
    fn language_id(&self) -> LanguageId {
        LanguageId::new("c")
    }

    fn display_name(&self) -> &'static str {
        "test C"
    }

    fn file_extensions(&self) -> &'static [&'static str] {
        &["c"]
    }

    fn tree_sitter_language(&self) -> Result<tree_sitter::Language, AdapterError> {
        bonsai_lang_api::kit::language_from_pack("c")
    }

    fn parse_recovery_edits(
        &self,
        snapshot: &bonsai_lang_api::FileSnapshot,
        vfs: &Vfs,
        tree: &Tree,
    ) -> Vec<bonsai_lang_api::ParseRecoveryEdit> {
        bonsai_lang_api::c_family_declaration_macro_recovery_edits(
            snapshot,
            vfs,
            tree,
            &["va_arg", "__builtin_va_arg"],
        )
    }

    fn capabilities(&self) -> LanguageCapabilities {
        LanguageCapabilities::unsupported()
    }

    fn extract_declarations(&self, file: FileId, _ctx: &AdapterContext<'_>) -> DeclIndex {
        DeclIndex {
            file,
            ..DeclIndex::default()
        }
    }

    fn extract_imports(&self, file: FileId, _ctx: &AdapterContext<'_>) -> ImportIndex {
        ImportIndex {
            file,
            imports: Vec::new(),
        }
    }
}

fn test_c_adapter() -> AdapterArc {
    Arc::new(TestCAdapter)
}

#[test]
fn byte_offsets_saturate_instead_of_wrapping() {
    assert_eq!(saturating_byte_offset(u64::MAX as usize), u64::MAX);
}

#[test]
fn zero_parse_timeout_disables_timeout() {
    assert_eq!(parse_timeout_millis(0), None);
    assert_eq!(parse_timeout_millis(5), Some(Duration::from_millis(5)));
}

#[test]
fn parser_default_is_uncapped_when_environment_is_unset() {
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _lock = ENV_LOCK.lock().expect("parse-timeout env lock");
    let previous = std::env::var_os("BONSAI_PARSE_TIMEOUT_MS");
    std::env::remove_var("BONSAI_PARSE_TIMEOUT_MS");

    assert_eq!(ParserOptions::default().parse_timeout, None);

    if let Some(previous) = previous {
        std::env::set_var("BONSAI_PARSE_TIMEOUT_MS", previous);
    } else {
        std::env::remove_var("BONSAI_PARSE_TIMEOUT_MS");
    }
}

#[test]
fn parse_timeout_diagnostic_is_file_level_warning() {
    let diagnostic = parse_timeout_diagnostic(FileId::new(1), 42, Duration::from_millis(7));
    assert_eq!(diagnostic.severity, Severity::Warning);
    assert_eq!(diagnostic.code.as_deref(), Some("parse-timeout"));
    assert_eq!(diagnostic.span, bonsai_common::Span::new(FileId::new(1), 0, 42));
    assert_eq!(diagnostic.message, "file skipped: parse timeout after 7 ms");
}

#[test]
fn c_variadic_pointer_type_recovers_without_changing_source_coordinates() {
    let source = "void exec_all(int count, ...) {\n\
                  va_list args;\n\
                  char *cmd = va_arg(args, char *);\n\
                  sink(cmd);\n\
                  }\n";
    let cache = ParserCache::with_options(ParserOptions::with_parse_timeout(None));
    let vfs = Vfs::new();
    let file = vfs.write("variadic.c", source);
    let parsed = cache
        .parse(file, &test_c_adapter(), &vfs)
        .expect("parse recovered C variadic fixture");

    assert!(
        parsed.used_recovery,
        "pointer type operand should use grammar recovery"
    );
    assert!(!parsed.tree.root_node().has_error());
    assert!(parsed.diagnostics.is_empty());
    assert_eq!(parsed.source_text(), source);
}

#[test]
fn adapter_host_normalization_runs_before_the_first_parse() {
    let source = "<html>\ndef embedded():\n    return 1\n";
    let cache = ParserCache::with_options(ParserOptions::with_parse_timeout(None));
    let vfs = Vfs::new();
    let file = vfs.write("template.py", source);
    let parsed = cache
        .parse(file, &test_python_adapter(), &vfs)
        .expect("parse normalized host-language fixture");

    assert!(parsed.used_recovery);
    assert!(!parsed.tree.root_node().has_error());
    assert!(parsed.diagnostics.is_empty());
    assert_eq!(parsed.source_text(), source);
    let function = parsed
        .tree
        .root_node()
        .named_child(0)
        .expect("embedded function declaration");
    assert_eq!(function.kind(), "function_definition");
    assert_eq!(function.start_byte(), 7);
}

#[test]
fn repeated_exact_snapshot_reuses_parsed_file_and_tree_arcs() {
    let cache = ParserCache::with_options(ParserOptions::with_parse_timeout(None));
    let vfs = Vfs::new();
    let file = vfs.write("fixture.py", "def cached():\n    return 1\n");
    let adapter = test_python_adapter();

    let first = cache.parse(file, &adapter, &vfs).expect("first parse");
    let second = cache.parse(file, &adapter, &vfs).expect("cached parse");

    assert!(Arc::ptr_eq(&first, &second));
    assert!(Arc::ptr_eq(&first.tree, &second.tree));
}

#[test]
fn exact_release_evicts_only_the_lowered_workspace_file_and_language() {
    let cache = ParserCache::with_options(ParserOptions::with_parse_timeout(None));
    let vfs = Vfs::new();
    let released_file = vfs.write("released.py", "def released():\n    return 1\n");
    let retained_file = vfs.write("retained.py", "def retained():\n    return 2\n");
    let adapter = test_python_adapter();

    let released_before = cache
        .parse(released_file, &adapter, &vfs)
        .expect("parse released fixture");
    let retained_before = cache
        .parse(retained_file, &adapter, &vfs)
        .expect("parse retained fixture");

    cache.release(released_file, &adapter, &vfs);

    let released_after = cache
        .parse(released_file, &adapter, &vfs)
        .expect("reparse released fixture");
    let retained_after = cache
        .parse(retained_file, &adapter, &vfs)
        .expect("reuse retained fixture");
    assert!(!Arc::ptr_eq(&released_before, &released_after));
    assert!(!Arc::ptr_eq(&released_before.tree, &released_after.tree));
    assert!(Arc::ptr_eq(&retained_before, &retained_after));
    assert!(Arc::ptr_eq(&retained_before.tree, &retained_after.tree));
}

#[test]
fn reparsing_an_edit_keeps_tree_and_source_on_the_same_version() {
    let cache = ParserCache::with_options(ParserOptions::with_parse_timeout(None));
    let vfs = Vfs::new();
    let file = vfs.write("fixture.py", "def before():\n    return 1\n");
    let adapter = test_python_adapter();
    let before = cache.parse(file, &adapter, &vfs).expect("initial parse");

    vfs.write("fixture.py", "def after():\n    return 2\n");
    let after = cache.parse(file, &adapter, &vfs).expect("edited parse");

    assert_eq!(after.version, before.version + 1);
    assert_eq!(after.source_text(), "def after():\n    return 2\n");
    assert_eq!(
        first_node_text(&after.tree, after.source_text(), "identifier").as_deref(),
        Some("after")
    );
    assert!(!Arc::ptr_eq(&before.tree, &after.tree));
}

#[test]
fn cache_identity_includes_the_vfs_instance() {
    let cache = ParserCache::with_options(ParserOptions::with_parse_timeout(None));
    let first_vfs = Vfs::new();
    let second_vfs = Vfs::new();
    let first_file = first_vfs.write("fixture.py", "def first():\n    pass\n");
    let second_file = second_vfs.write("fixture.py", "def second():\n    pass\n");
    assert_eq!(first_file, second_file, "fixture must exercise colliding FileIds");
    let adapter = test_python_adapter();

    let first = cache
        .parse(first_file, &adapter, &first_vfs)
        .expect("first workspace parse");
    let second = cache
        .parse(second_file, &adapter, &second_vfs)
        .expect("second workspace parse");

    assert_eq!(first.source_text(), "def first():\n    pass\n");
    assert_eq!(second.source_text(), "def second():\n    pass\n");
    assert!(!Arc::ptr_eq(&first.tree, &second.tree));
}

#[test]
fn same_language_worker_checkouts_are_not_globally_serialized() {
    use std::sync::{mpsc, Condvar, Mutex as StdMutex};

    let cache = ParserCache::with_options(ParserOptions::with_parse_timeout(None));
    let release = Arc::new((StdMutex::new(false), Condvar::new()));
    let (entered_tx, entered_rx) = mpsc::channel();
    let mut workers = Vec::new();
    for _ in 0..2 {
        let cache = cache.clone();
        let release = Arc::clone(&release);
        let entered_tx = entered_tx.clone();
        workers.push(std::thread::spawn(move || {
            let _parser = cache.checkout_parser("python");
            entered_tx.send(()).expect("announce parser checkout");
            let (lock, wake) = &*release;
            let mut released = lock.lock().expect("release lock");
            while !*released {
                released = wake.wait(released).expect("release wait");
            }
        }));
    }
    drop(entered_tx);

    let first_entered = entered_rx.recv_timeout(Duration::from_secs(2));
    let second_entered = entered_rx.recv_timeout(Duration::from_secs(2));
    {
        let (lock, wake) = &*release;
        *lock.lock().expect("release lock") = true;
        wake.notify_all();
    }
    for worker in workers {
        worker.join().expect("parser worker");
    }

    assert!(first_entered.is_ok(), "first worker never checked out a parser");
    assert!(
        second_entered.is_ok(),
        "same-language worker was serialized behind the first parser checkout"
    );
}

#[test]
fn replacement_edit_uses_utf8_boundaries_and_exact_points() {
    let old = "let café = 1;\nnext();\n";
    let new = "let cañon = 22;\nnext();\n";
    let edit = single_replacement_edit(old, new);

    assert!(old.is_char_boundary(edit.start_byte));
    assert!(old.is_char_boundary(edit.old_end_byte));
    assert!(new.is_char_boundary(edit.new_end_byte));
    assert_eq!(edit.start_position, point_at_byte(old, edit.start_byte));
    assert_eq!(edit.old_end_position, point_at_byte(old, edit.old_end_byte));
    assert_eq!(edit.new_end_position, point_at_byte(new, edit.new_end_byte));
}

fn first_node_text(tree: &Tree, source: &str, kind: &str) -> Option<String> {
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
