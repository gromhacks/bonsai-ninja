use bonsai_db::AnalyzerDb;
use bonsai_lang_api::{DeclKind, LanguageAdapter, LanguageRegistry};
use bonsai_vfs::Vfs;
use std::sync::Arc;

fn db_for(adapter: Arc<dyn LanguageAdapter>, path: &str, source: &str) -> AnalyzerDb {
    let vfs = Arc::new(Vfs::new());
    vfs.write(path.to_string(), Arc::<str>::from(source));
    let registry = Arc::new(LanguageRegistry::new());
    registry.register(adapter);
    let db = AnalyzerDb::new(vfs, registry);
    for file in db.vfs().all_files() {
        let _ = db.decl_index(file);
    }
    db
}

fn decl_kinds(db: &AnalyzerDb, name: &str) -> Vec<DeclKind> {
    let global = db.global_index();
    let mut kinds = Vec::new();
    for file in global.all_files() {
        for decl in global.decls_in(file) {
            if decl.name == name {
                kinds.push(decl.kind);
            }
        }
    }
    assert!(!kinds.is_empty(), "missing declaration `{name}`");
    kinds
}

fn assert_not_constructor(db: &AnalyzerDb, name: &str) {
    let kinds = decl_kinds(db, name);
    assert!(
        !kinds.contains(&DeclKind::Constructor),
        "`{name}` must not be classified as a constructor; kinds={kinds:?}"
    );
}

fn assert_has_constructor(db: &AnalyzerDb, name: &str) {
    let kinds = decl_kinds(db, name);
    assert!(
        kinds.contains(&DeclKind::Constructor),
        "`{name}` must include a constructor decl; kinds={kinds:?}"
    );
}

#[test]
fn constructor_method_vocabulary_is_adapter_owned_without_legacy_fallback() {
    let adapters: Vec<(&str, Arc<dyn LanguageAdapter>)> = vec![
        ("c", Arc::new(bonsai_lang_c::CAdapter::new())),
        ("cpp", Arc::new(bonsai_lang_cpp::CppAdapter::new())),
        ("csharp", Arc::new(bonsai_lang_csharp::CSharpAdapter::new())),
        ("dart", Arc::new(bonsai_lang_dart::DartAdapter::new())),
        ("elixir", Arc::new(bonsai_lang_elixir::ElixirAdapter::new())),
        ("erlang", Arc::new(bonsai_lang_erlang::ErlangAdapter::new())),
        ("go", Arc::new(bonsai_lang_go::GoAdapter::new())),
        ("java", Arc::new(bonsai_lang_java::JavaAdapter::new())),
        (
            "javascript",
            Arc::new(bonsai_lang_javascript::JavaScriptAdapter::new()),
        ),
        ("kotlin", Arc::new(bonsai_lang_kotlin::KotlinAdapter::new())),
        ("lua", Arc::new(bonsai_lang_lua::LuaAdapter::new())),
        ("objc", Arc::new(bonsai_lang_objc::ObjCAdapter::new())),
        ("perl", Arc::new(bonsai_lang_perl::PerlAdapter::new())),
        ("php", Arc::new(bonsai_lang_php::PhpAdapter::new())),
        ("python", Arc::new(bonsai_lang_python::PythonAdapter::new())),
        ("ruby", Arc::new(bonsai_lang_ruby::RubyAdapter::new())),
        ("rust", Arc::new(bonsai_lang_rust::RustAdapter::new())),
        ("scala", Arc::new(bonsai_lang_scala::ScalaAdapter::new())),
        ("solidity", Arc::new(bonsai_lang_solidity::SolidityAdapter::new())),
        ("swift", Arc::new(bonsai_lang_swift::SwiftAdapter::new())),
        (
            "typescript",
            Arc::new(bonsai_lang_typescript::TypeScriptAdapter::new()),
        ),
    ];

    for (lang, adapter) in adapters {
        let caps = adapter.capabilities();
        assert_eq!(
            caps.effective_constructor_method_names(),
            caps.constructor_method_names,
            "{lang} must not inherit a cross-language constructor-name fallback"
        );
    }
}

#[test]
fn c_init_function_is_not_a_constructor() {
    let db = db_for(
        Arc::new(bonsai_lang_c::CAdapter::new()),
        "demo.c",
        "void init(void) {}\n",
    );

    assert_not_constructor(&db, "init");
}

#[test]
fn java_init_method_is_not_a_constructor_but_constructor_decl_is() {
    let db = db_for(
        Arc::new(bonsai_lang_java::JavaAdapter::new()),
        "Demo.java",
        "class Demo { Demo(String value) {} void init(String value) {} }\n",
    );

    assert_has_constructor(&db, "Demo");
    assert_not_constructor(&db, "init");
}

#[test]
fn javascript_init_method_is_not_a_constructor_but_constructor_decl_is() {
    let db = db_for(
        Arc::new(bonsai_lang_javascript::JavaScriptAdapter::new()),
        "demo.js",
        "class Demo { constructor(value) {} init(value) {} }\n",
    );

    assert_has_constructor(&db, "constructor");
    assert_not_constructor(&db, "init");
}

#[test]
fn objc_initwith_method_is_constructor_but_initialize_is_not() {
    let db = db_for(
        Arc::new(bonsai_lang_objc::ObjCAdapter::new()),
        "Demo.m",
        "@interface Demo\n\
         - (instancetype)initWithData:(id)data;\n\
         + (void)initialize;\n\
         @end\n\
         @implementation Demo\n\
         - (instancetype)initWithData:(id)data { return self; }\n\
         + (void)initialize {}\n\
         @end\n",
    );

    assert_has_constructor(&db, "initWithData");
    assert_not_constructor(&db, "initialize");
}
