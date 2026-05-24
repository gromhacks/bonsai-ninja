//! P0.3: super-dispatch resolution. The engine recognizes the
//! per-language super-receiver markers (`super`/`parent`/`base`) and
//! resolves the call to the parent class's method via
//! `resolve_super_method_candidates`.
//!
//! Verified across languages with explicit super receivers: Python
//! (`super().method()`), JavaScript/TypeScript (`super.method()`),
//! C# (`base.method()`), Dart (`super.method()`), and others covered
//! by the matrix.

use bonsai_common::{FuncId, SymbolId};
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
    let matches = bonsai_resolve::resolve_callable(&g, name);
    assert!(!matches.is_empty(), "expected `{name}` resolvable");
    matches[0]
}

fn seed(names: &[&str]) -> TokenSet {
    names.iter().map(|n| (*n).to_string()).collect()
}

fn config(_: &[&str]) -> InterTaintConfig {
    InterTaintConfig {
        budget: 512,
        ..Default::default()
    }
}

fn super_target_in_chain(
    result: &bonsai_taint::InterTaintResult,
    db: &AnalyzerDb,
    parent_name: &str,
) -> bool {
    let g = db.global_index();
    let parent_funcs: Vec<SymbolId> = bonsai_resolve::resolve_callable(&g, parent_name)
        .iter()
        .map(|f| SymbolId::new(f.raw()))
        .collect();
    result
        .call_records
        .iter()
        .any(|c| parent_funcs.contains(&SymbolId::new(c.callee.raw())))
}

fn super_target_in_class_chain(
    result: &bonsai_taint::InterTaintResult,
    db: &AnalyzerDb,
    method_name: &str,
    class_name: &str,
) -> bool {
    let g = db.global_index();
    result.call_records.iter().any(|record| {
        g.decl_of(SymbolId::new(record.callee.raw())).is_some_and(|decl| {
            decl.name == method_name
                && decl
                    .parent
                    .and_then(|parent| g.decl_of(parent))
                    .is_some_and(|parent| {
                        parent.name == class_name
                            || parent
                                .qualified_name
                                .as_deref()
                                .is_some_and(|qn| qn.contains(class_name))
                    })
        })
    })
}

#[test]
fn python_super_resolves_to_parent_method() {
    let src = "
class Parent:
    def handle(self, data):
        sink(data)

class Child(Parent):
    def handle(self, data):
        super().handle(data)
";
    let db = ws(
        Arc::new(bonsai_lang_python::PythonAdapter::new()),
        &[("a.py", src)],
    );
    let entry = func(&db, "handle");
    let result = interprocedural_taint(entry, &seed(&["data"]), &config(&[]), &db);
    assert!(
        super_target_in_chain(&result, &db, "handle"),
        "Python super().handle() must resolve to a parent's `handle` via super_dispatch"
    );
}

/// Pick the FuncId of `name` whose enclosing decl resides inside the
/// class named `class_name`. With shadowing, a workspace can have two
/// methods with the same name in different classes; tests need the
/// child's method specifically so the super-call has somewhere to go.
fn func_in_class(db: &AnalyzerDb, name: &str, class_name: &str) -> FuncId {
    let g = db.global_index();
    let matches = bonsai_resolve::resolve_callable(&g, name);
    for func_id in &matches {
        if let Some(decl) = g.decl_of(SymbolId::new(func_id.raw())) {
            if decl
                .qualified_name
                .as_deref()
                .is_some_and(|qn| qn.contains(class_name))
            {
                return *func_id;
            }
        }
    }
    matches[0]
}

fn func_in_file(db: &AnalyzerDb, name: &str, file_suffix: &str) -> FuncId {
    let g = db.global_index();
    let matches = bonsai_resolve::resolve_callable(&g, name);
    for func_id in &matches {
        if let Some(decl) = g.decl_of(SymbolId::new(func_id.raw())) {
            if g.declaring_file(decl.symbol)
                .and_then(|file| db.vfs().path(file).ok())
                .is_some_and(|path| path.to_string_lossy().ends_with(file_suffix))
            {
                return *func_id;
            }
        }
    }
    panic!("expected `{name}` in file ending {file_suffix}; matches={matches:?}");
}

#[test]
fn python_super_resolves_aliased_parent_method() {
    let db = ws(
        Arc::new(bonsai_lang_python::PythonAdapter::new()),
        &[
            (
                "parent.py",
                "class Parent:\n    def handle(self, data):\n        sink(data)\n",
            ),
            (
                "child.py",
                "from parent import Parent as P\n\nclass Child(P):\n    def handle(self, data):\n        super().handle(data)\n",
            ),
        ],
    );
    let entry = func_in_file(&db, "handle", "child.py");
    let result = interprocedural_taint(entry, &seed(&["data"]), &config(&[]), &db);
    let g = db.global_index();
    let reached_parent = result.call_records.iter().any(|record| {
        g.decl_of(SymbolId::new(record.callee.raw())).is_some_and(|decl| {
            decl.name == "handle"
                && g.declaring_file(decl.symbol)
                    .and_then(|file| db.vfs().path(file).ok())
                    .is_some_and(|path| path.to_string_lossy().ends_with("parent.py"))
        })
    });
    assert!(
        reached_parent,
        "super().handle() must resolve through aliased base class P -> parent.Parent; records={:#?}",
        result.call_records
    );
}

#[test]
fn csharp_base_resolves_to_parent_method() {
    let src = "
class Parent { public virtual void Handle(string data) { Sink(data); } }
class Child : Parent {
    public override void Handle(string data) { base.Handle(data); }
}
";
    let db = ws(
        Arc::new(bonsai_lang_csharp::CSharpAdapter::new()),
        &[("Demo.cs", src)],
    );
    let entry = func_in_class(&db, "Handle", "Child");
    let result = interprocedural_taint(entry, &seed(&["data"]), &config(&[]), &db);
    assert!(
        super_target_in_chain(&result, &db, "Handle"),
        "C# base.Handle() must resolve to parent's `Handle` (the engine treats `base` as a super-receiver)"
    );
}

#[test]
fn dart_super_resolves_to_parent_method() {
    let src = "
class Parent { void handle(String data) { sink(data); } }
class Child extends Parent {
  @override
  void handle(String data) { super.handle(data); }
}
";
    let db = ws(Arc::new(bonsai_lang_dart::DartAdapter::new()), &[("a.dart", src)]);
    let entry = func_in_class(&db, "handle", "Child");
    let result = interprocedural_taint(entry, &seed(&["data"]), &config(&[]), &db);
    assert!(
        super_target_in_chain(&result, &db, "handle"),
        "Dart super.handle() must resolve to parent's `handle`"
    );
}

#[test]
fn javascript_super_resolves_to_parent_method() {
    let src = "
class Parent {
  handle(data) { sink(data); }
}

class Child extends Parent {
  handle(data) { super.handle(data); }
}
";
    let db = ws(
        Arc::new(bonsai_lang_javascript::JavaScriptAdapter::new()),
        &[("a.js", src)],
    );
    let entry = func_in_class(&db, "handle", "Child");
    let result = interprocedural_taint(entry, &seed(&["data"]), &config(&[]), &db);
    assert!(
        super_target_in_class_chain(&result, &db, "handle", "Parent"),
        "JavaScript super.handle() must resolve to Parent.handle instead of name-only fallback; records={:#?}",
        result.call_records
    );
}

#[test]
fn typescript_super_resolves_aliased_parent_method_across_files() {
    let db = ws(
        Arc::new(bonsai_lang_typescript::TypeScriptAdapter::new()),
        &[
            (
                "base.ts",
                "export class BaseHandler {\n  handle(data: string) { sink(data); }\n}\n",
            ),
            (
                "child.ts",
                "import { BaseHandler as ParentHandler } from './base';\n\nexport class Child extends ParentHandler {\n  handle(data: string) { super.handle(data); }\n}\n",
            ),
        ],
    );
    let entry = func_in_file(&db, "handle", "child.ts");
    let result = interprocedural_taint(entry, &seed(&["data"]), &config(&[]), &db);
    assert!(
        super_target_in_class_chain(&result, &db, "handle", "BaseHandler"),
        "TypeScript aliased cross-file super.handle() must resolve to BaseHandler.handle; records={:#?}",
        result.call_records
    );
}
