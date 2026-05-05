//! P0.4: receiver_field_writes is populated by the kit for every
//! adapter that declares `implicit_receiver_names` (= every OO
//! adapter). Audit-script literal-string match was the only gap; this
//! test asserts the field is genuinely populated end-to-end across
//! Java, Python, JavaScript, TypeScript, C#.

use bonsai_db::AnalyzerDb;
use bonsai_lang_api::{LanguageAdapter, LanguageRegistry};
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

fn first_nonempty_field_writes(db: &AnalyzerDb) -> Vec<bonsai_lang_api::FieldWrite> {
    let g = db.global_index();
    for file in g.all_files() {
        for decl in g.decls_in(file) {
            if !decl.receiver_field_writes.is_empty() {
                return decl.receiver_field_writes.clone();
            }
        }
    }
    Vec::new()
}

#[test]
fn python_self_field_write_populates() {
    let src = "
class Handler:
    def m1(self, x):
        self.cmd = x

    def m2(self):
        run(self.cmd)
";
    let db = ws(
        Arc::new(bonsai_lang_python::PythonAdapter::new()),
        &[("a.py", src)],
    );
    let writes = first_nonempty_field_writes(&db);
    assert!(
        writes.iter().any(|w| w.target == "self.cmd"),
        "Python `self.cmd = x` must populate receiver_field_writes; got {writes:?}"
    );
}

#[test]
fn java_this_field_write_populates() {
    let src = "
class Handler {
    String cmd;
    void m1(String x) { this.cmd = x; }
    void m2() { Runtime.getRuntime().exec(this.cmd); }
}
";
    let db = ws(
        Arc::new(bonsai_lang_java::JavaAdapter::new()),
        &[("Handler.java", src)],
    );
    let writes = first_nonempty_field_writes(&db);
    assert!(
        writes.iter().any(|w| w.target.contains("cmd")),
        "Java `this.cmd = x` must populate receiver_field_writes; got {writes:?}"
    );
}

#[test]
fn javascript_this_field_write_populates() {
    let src = "
class Handler {
    m1(x) { this.cmd = x; }
    m2() { exec(this.cmd); }
}
";
    let db = ws(
        Arc::new(bonsai_lang_javascript::JavaScriptAdapter::new()),
        &[("a.js", src)],
    );
    let writes = first_nonempty_field_writes(&db);
    assert!(
        writes.iter().any(|w| w.target.contains("cmd")),
        "JavaScript `this.cmd = x` must populate receiver_field_writes; got {writes:?}"
    );
}

#[test]
fn typescript_this_field_write_populates() {
    let src = "
class Handler {
    cmd: string;
    m1(x: string) { this.cmd = x; }
    m2() { exec(this.cmd); }
}
";
    let db = ws(
        Arc::new(bonsai_lang_typescript::TypeScriptAdapter::new()),
        &[("a.ts", src)],
    );
    let writes = first_nonempty_field_writes(&db);
    assert!(
        writes.iter().any(|w| w.target.contains("cmd")),
        "TypeScript `this.cmd = x` must populate receiver_field_writes; got {writes:?}"
    );
}

#[test]
fn csharp_this_field_write_populates() {
    let src = "
class Handler {
    string cmd;
    void M1(string x) { this.cmd = x; }
    void M2() { Run(this.cmd); }
}
";
    let db = ws(
        Arc::new(bonsai_lang_csharp::CSharpAdapter::new()),
        &[("Handler.cs", src)],
    );
    let writes = first_nonempty_field_writes(&db);
    assert!(
        writes.iter().any(|w| w.target.contains("cmd")),
        "C# `this.cmd = x` must populate receiver_field_writes; got {writes:?}"
    );
}
