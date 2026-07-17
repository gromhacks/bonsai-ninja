//! P2.2: Typed-exception narrowing for Java/Kotlin/C#. Adapters
//! populate `Throw::thrown_type` and `Try::catch_types` from
//! syntactic types; the engine seeds the catch param only when at
//! least one body throw is type-assignable to one of the catch
//! types, so a catch arm whose declared type can't catch the throw
//! does NOT inherit taint.

use bonsai_common::FuncId;
use bonsai_db::AnalyzerDb;
use bonsai_lang_api::{LanguageAdapter, LanguageRegistry};
use bonsai_taint::{interprocedural_taint, InterTaintConfig, TokenSet};
use bonsai_vfs::Vfs;
use std::sync::Arc;

fn ws(adapter: Arc<dyn LanguageAdapter>, files: &[(&str, &str)]) -> AnalyzerDb {
    let vfs = Arc::new(Vfs::new());
    for (path, source) in files {
        vfs.write((*path).to_string(), Arc::<str>::from(*source));
    }
    let registry = Arc::new(LanguageRegistry::new());
    registry.register(adapter);
    let db = AnalyzerDb::new(vfs, registry);
    for f in db.vfs().all_files() {
        let _ = db.decl_index(f);
    }
    db
}

fn func(db: &AnalyzerDb, name: &str) -> FuncId {
    let g = db.global_index();
    *bonsai_resolve::resolve_callable(&g, name)
        .first()
        .expect("function exists")
}

fn seed(names: &[&str]) -> TokenSet {
    names.iter().map(|n| (*n).to_string()).collect()
}

fn config() -> InterTaintConfig {
    InterTaintConfig::default()
}

fn body_calls_sink_with_taint(
    result: &bonsai_taint::InterTaintResult,
    _db: &AnalyzerDb,
    sink_name: &str,
) -> bool {
    // Engine surfaces sink reachability via `tainted_calls` (resolved
    // and unresolved calls with at least one tainted arg). The
    // resolved cross-fn `call_records` only fires when the sink is
    // declared in the workspace; for fixtures using bare `sink(e)` /
    // `Sink(e)` calls without a definition, `tainted_calls` is the
    // right signal.
    result
        .tainted_calls
        .iter()
        .any(|c| c.name == sink_name && !c.tainted_args.is_empty())
}

#[test]
fn java_io_exception_does_not_taint_runtime_exception_catch() {
    // body throws an IOException; the catch arm catches RuntimeException.
    // An IOException can't be caught by a RuntimeException arm in real
    // Java semantics. With Exact precision, the catch param `e` should
    // NOT be seeded with taint, so the sink call inside the catch
    // body sees a clean state.
    let src = "
class C {
    void entry(String tainted) {
        try {
            throw new IOException(tainted);
        } catch (RuntimeException e) {
            sink(e);
        }
    }
}
class IOException { IOException(Object x) {} }
class RuntimeException { RuntimeException(Object x) {} }
";
    let db = ws(Arc::new(bonsai_lang_java::JavaAdapter::new()), &[("C.java", src)]);
    let entry = func(&db, "entry");
    let result = interprocedural_taint(entry, &seed(&["tainted"]), &config(), &db);
    assert!(
        !body_calls_sink_with_taint(&result, &db, "sink"),
        "Java RuntimeException catch must not inherit taint from IOException throw"
    );
}

#[test]
fn java_matching_catch_arm_inherits_taint() {
    // Same fixture but with the catch arm matching the throw type.
    // Engine should seed the catch param so the sink fires.
    let src = "
class C {
    void entry(String tainted) {
        try {
            throw new IOException(tainted);
        } catch (IOException e) {
            sink(e);
        }
    }
}
class IOException { IOException(Object x) {} }
";
    let db = ws(Arc::new(bonsai_lang_java::JavaAdapter::new()), &[("C.java", src)]);
    let entry = func(&db, "entry");
    let result = interprocedural_taint(entry, &seed(&["tainted"]), &config(), &db);
    assert!(
        body_calls_sink_with_taint(&result, &db, "sink"),
        "matching IOException catch arm must inherit taint from IOException throw"
    );
}

#[test]
fn java_declared_subtype_reaches_base_catch() {
    let src = "
class C {
    void entry(String tainted) {
        try {
            throw new IOException(tainted);
        } catch (AppException e) {
            sink(e);
        }
    }
}
class AppException { AppException(Object x) {} }
class IOException extends AppException { IOException(Object x) { super(x); } }
";
    let db = ws(Arc::new(bonsai_lang_java::JavaAdapter::new()), &[("C.java", src)]);
    let entry = func(&db, "entry");
    let result = interprocedural_taint(entry, &seed(&["tainted"]), &config(), &db);
    assert!(
        body_calls_sink_with_taint(&result, &db, "sink"),
        "tree-sitter class bases must prove IOException assignable to AppException"
    );
}

#[test]
fn csharp_typed_catch_arm_disambiguation() {
    let src = "
class C {
    void Entry(string tainted) {
        try {
            throw new IOException(tainted);
        } catch (FormatException e) {
            Sink(e);
        }
    }
}
class IOException { public IOException(object x) {} }
class FormatException { public FormatException(object x) {} }
";
    let db = ws(
        Arc::new(bonsai_lang_csharp::CSharpAdapter::new()),
        &[("C.cs", src)],
    );
    let entry = func(&db, "Entry");
    let result = interprocedural_taint(entry, &seed(&["tainted"]), &config(), &db);
    assert!(
        !body_calls_sink_with_taint(&result, &db, "Sink"),
        "C# FormatException catch must not inherit taint from IOException throw"
    );
}

#[test]
fn kotlin_typed_catch_arm_disambiguation() {
    let src = "
class C {
    fun entry(tainted: String) {
        try {
            throw IOException(tainted)
        } catch (e: NumberFormatException) {
            sink(e)
        }
    }
}
class IOException(val x: String)
class NumberFormatException(val x: String)
";
    let db = ws(
        Arc::new(bonsai_lang_kotlin::KotlinAdapter::new()),
        &[("C.kt", src)],
    );
    let entry = func(&db, "entry");
    let result = interprocedural_taint(entry, &seed(&["tainted"]), &config(), &db);
    assert!(
        !body_calls_sink_with_taint(&result, &db, "sink"),
        "Kotlin NumberFormatException catch must not inherit taint from IOException throw"
    );
}

#[test]
fn empty_catch_types_falls_back_to_conservative_seed() {
    // For Python (which doesn't populate catch_types), the existing
    // conservative seed-on-any-tainted-throw behavior must still work.
    let src = "
def entry(tainted):
    try:
        raise ValueError(tainted)
    except Exception as e:
        sink(e)
";
    let db = ws(
        Arc::new(bonsai_lang_python::PythonAdapter::new()),
        &[("a.py", src)],
    );
    let entry = func(&db, "entry");
    let result = interprocedural_taint(entry, &seed(&["tainted"]), &config(), &db);
    assert!(
        body_calls_sink_with_taint(&result, &db, "sink"),
        "Python (no catch_types) must keep conservative seed-on-tainted-throw behavior"
    );
}
