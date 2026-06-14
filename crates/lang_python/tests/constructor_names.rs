use bonsai_db::AnalyzerDb;
use bonsai_lang_api::{DeclKind, LanguageRegistry};
use bonsai_vfs::Vfs;
use std::sync::Arc;

fn python_db(source: &str) -> AnalyzerDb {
    let vfs = Arc::new(Vfs::new());
    vfs.write("a.py".to_string(), Arc::<str>::from(source));
    let registry = Arc::new(LanguageRegistry::new());
    registry.register(Arc::new(bonsai_lang_python::PythonAdapter::new()));
    let db = AnalyzerDb::new(vfs, registry);
    for file in db.vfs().all_files() {
        let _ = db.decl_index(file);
    }
    db
}

fn decl_kind(db: &AnalyzerDb, name: &str) -> DeclKind {
    let global = db.global_index();
    for file in global.all_files() {
        for decl in global.decls_in(file) {
            if decl.name == name {
                return decl.kind;
            }
        }
    }
    panic!("missing declaration `{name}`")
}

fn decl_receiver_index(db: &AnalyzerDb, name: &str) -> Option<usize> {
    let global = db.global_index();
    for file in global.all_files() {
        for decl in global.decls_in(file) {
            if decl.name == name {
                return decl.receiver_param_index;
            }
        }
    }
    panic!("missing declaration `{name}`")
}

#[test]
fn python_only_dunder_init_is_constructor() {
    let db = python_db(
        r#"
class Repo:
    def __init__(self, data):
        self.data = data

    def init(self, data):
        return data
"#,
    );

    assert_eq!(decl_kind(&db, "__init__"), DeclKind::Constructor);
    assert_ne!(
        decl_kind(&db, "init"),
        DeclKind::Constructor,
        "Python adapters must not inherit the cross-language `init` constructor name"
    );
}

#[test]
fn python_class_functions_are_methods_with_receiver_params() {
    let db = python_db(
        r#"
class Repo:
    def persist(self):
        return self.data
"#,
    );

    assert_eq!(decl_kind(&db, "persist"), DeclKind::Method);
    assert_eq!(decl_receiver_index(&db, "persist"), Some(0));
}

fn decl_type_alias(db: &AnalyzerDb, fn_name: &str, var: &str) -> Option<String> {
    let global = db.global_index();
    for file in global.all_files() {
        for decl in global.decls_in(file) {
            if decl.name == fn_name {
                return decl
                    .type_aliases
                    .iter()
                    .find(|alias| alias.name == var)
                    .map(|alias| alias.type_name.clone());
            }
        }
    }
    panic!("missing declaration `{fn_name}`")
}

#[test]
fn local_constructor_assignment_infers_receiver_type() {
    // `conn = ldap3.Connection(server)` should type `conn` as `Connection`
    // so `receiver_type_in` / `[Type, method]` rules resolve the receiver
    // semantically instead of relying on a loosened package gate.
    let db = python_db(
        r#"
import ldap3

def handler(server, user_input):
    conn = ldap3.Connection(server)
    return conn.search("dc=example", user_input)
"#,
    );
    assert_eq!(
        decl_type_alias(&db, "handler", "conn").as_deref(),
        Some("Connection"),
        "qualified constructor `ldap3.Connection(...)` should infer type `Connection`"
    );
}

#[test]
fn local_lowercase_factory_call_does_not_infer_type() {
    // `s = socket.socket()` is not a constructor by the PascalCase
    // convention — must NOT mint a bogus receiver type.
    let db = python_db(
        r#"
import socket

def handler():
    s = socket.socket()
    return s
"#,
    );
    assert_eq!(
        decl_type_alias(&db, "handler", "s"),
        None,
        "lowercase `socket.socket()` tail must not be treated as a constructor"
    );
}
