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

fn decl_param_default_calls(db: &AnalyzerDb, fn_name: &str, param: &str) -> Vec<String> {
    let global = db.global_index();
    for file in global.all_files() {
        for decl in global.decls_in(file) {
            if decl.name == fn_name {
                let idx = decl
                    .params
                    .iter()
                    .position(|candidate| candidate == param)
                    .unwrap_or_else(|| panic!("missing parameter `{param}` on `{fn_name}`"));
                return decl.param_default_calls.get(idx).cloned().unwrap_or_default();
            }
        }
    }
    panic!("missing declaration `{fn_name}`")
}

fn decl_param_annotations(db: &AnalyzerDb, fn_name: &str, param: &str) -> Vec<String> {
    let global = db.global_index();
    for file in global.all_files() {
        for decl in global.decls_in(file) {
            if decl.name == fn_name {
                let idx = decl
                    .params
                    .iter()
                    .position(|candidate| candidate == param)
                    .unwrap_or_else(|| panic!("missing parameter `{param}` on `{fn_name}`"));
                return decl.param_annotations.get(idx).cloned().unwrap_or_default();
            }
        }
    }
    panic!("missing declaration `{fn_name}`")
}

#[test]
fn local_constructor_assignment_infers_receiver_type() {
    // A workspace declaration, not identifier casing, proves that the call
    // constructs `Connection` and therefore types `conn`.
    let db = python_db(
        r#"
class Connection:
    def __init__(self, server):
        self.server = server

def handler(server, user_input):
    conn = Connection(server)
    return conn.search("dc=example", user_input)
"#,
    );
    assert_eq!(
        decl_type_alias(&db, "handler", "conn").as_deref(),
        Some("Connection"),
        "declared constructor `Connection(...)` should infer type `Connection`"
    );
}

#[test]
fn external_class_spelling_does_not_mint_a_type_without_stubs() {
    let db = python_db(
        r#"
import ldap3

def handler(server):
    conn = ldap3.Connection(server)
    return conn
"#,
    );
    assert_eq!(
        decl_type_alias(&db, "handler", "conn"),
        None,
        "an unresolved external member needs a stub or rulepack typing fact"
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

#[test]
fn annotated_receiver_field_type_propagates_without_constructor_arg_types() {
    let db = python_db(
        r#"
from typing import Annotated

class Router:
    def add_api_route(self, path):
        return path

class App:
    def __init__(self: "App", provider: Annotated[object, "metadata"]):
        self.router: Router = Router(provider)

    def register_route(self, path):
        return self.router.add_api_route(path)
"#,
    );

    assert_eq!(
        decl_type_alias(&db, "register_route", "self.router").as_deref(),
        Some("Router"),
        "the annotated field type, not a constructor argument type, must drive sibling receiver dispatch"
    );
}

#[test]
fn annotated_parameter_exposes_payload_type_for_receiver_dispatch() {
    let db = python_db(
        r#"
from typing import Annotated

class Request:
    def json(self):
        return {}

def handle(request: Annotated[Request, "framework metadata"]):
    return request.json()
"#,
    );

    assert_eq!(
        decl_type_alias(&db, "handle", "request").as_deref(),
        Some("Request")
    );
}

#[test]
fn parameter_default_call_is_generic_syntax_not_a_framework_type_guess() {
    let db = python_db(
        r#"
import framework as fw
from typing import Annotated

def handle(payload: Annotated[str, fw.Metadata()] = fw.Body(...), plain: str = "value"):
    return payload
"#,
    );

    assert_eq!(
        decl_param_default_calls(&db, "handle", "payload"),
        vec!["fw.Body".to_string()]
    );
    assert_eq!(
        decl_param_annotations(&db, "handle", "payload"),
        vec!["Metadata".to_string()],
        "Annotated metadata and a direct default call must remain distinct syntax facts"
    );
    assert!(decl_param_default_calls(&db, "handle", "plain").is_empty());
    assert_eq!(
        decl_type_alias(&db, "handle", "payload").as_deref(),
        Some("str"),
        "a default-call name must not override the declared runtime type"
    );
}
