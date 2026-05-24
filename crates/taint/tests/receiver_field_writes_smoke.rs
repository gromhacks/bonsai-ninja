//! P0.4: receiver_field_writes is populated by the kit for every
//! adapter that declares `implicit_receiver_names` (= every OO
//! adapter). Audit-script literal-string match was the only gap; this
//! test asserts the field is genuinely populated end-to-end across
//! Java, Python, JavaScript, TypeScript, C#, and adapters with
//! constructor/property syntax that needs adapter-specific lowering.

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

#[test]
fn dart_field_formal_constructor_populates() {
    let src = "
class Handler {
  String cmd;
  Handler(this.cmd);
}
";
    let db = ws(
        Arc::new(bonsai_lang_dart::DartAdapter::new()),
        &[("handler.dart", src)],
    );
    let writes = first_nonempty_field_writes(&db);
    assert!(
        writes.iter().any(|w| w.target == "this.cmd"),
        "Dart `Handler(this.cmd)` must populate receiver_field_writes; got {writes:?}"
    );
}

#[test]
fn kotlin_primary_constructor_property_populates() {
    let src = "
class Handler(val cmd: String)
";
    let db = ws(
        Arc::new(bonsai_lang_kotlin::KotlinAdapter::new()),
        &[("Handler.kt", src)],
    );
    let writes = first_nonempty_field_writes(&db);
    assert!(
        writes.iter().any(|w| w.target == "this.cmd"),
        "Kotlin `class Handler(val cmd: String)` must populate receiver_field_writes; got {writes:?}"
    );
}

#[test]
fn scala_constructor_val_populates() {
    let src = "
class Handler(val cmd: String) {
  def run(): String = cmd
}
";
    let db = ws(
        Arc::new(bonsai_lang_scala::ScalaAdapter::new()),
        &[("Handler.scala", src)],
    );
    let writes = first_nonempty_field_writes(&db);
    assert!(
        writes.iter().any(|w| w.target == "this.cmd"),
        "Scala `class Handler(val cmd: String)` must populate receiver_field_writes; got {writes:?}"
    );
}

#[test]
fn swift_initializer_self_field_populates() {
    let src = "
class Handler {
  let cmd: String
  init(_ cmd: String) { self.cmd = cmd }
}
";
    let db = ws(
        Arc::new(bonsai_lang_swift::SwiftAdapter::new()),
        &[("Handler.swift", src)],
    );
    let writes = first_nonempty_field_writes(&db);
    assert!(
        writes.iter().any(|w| w.target == "self.cmd"),
        "Swift `self.cmd = cmd` initializer must populate receiver_field_writes; got {writes:?}"
    );
}

#[test]
fn cpp_initializer_list_populates() {
    let src = "
#include <string>
class Handler {
public:
  std::string cmd;
  explicit Handler(std::string x) : cmd(std::move(x)) {}
};
";
    let db = ws(
        Arc::new(bonsai_lang_cpp::CppAdapter::new()),
        &[("handler.cpp", src)],
    );
    let writes = first_nonempty_field_writes(&db);
    assert!(
        writes.iter().any(|w| w.target == "this.cmd"),
        "C++ constructor initializer list must populate receiver_field_writes; got {writes:?}"
    );
}

#[test]
fn objc_ivar_initializer_populates() {
    let src = "
#import <Foundation/Foundation.h>
@interface Handler : NSObject
- (instancetype)initWithCmd:(NSString *)cmd;
@end
@implementation Handler
- (instancetype)initWithCmd:(NSString *)cmd {
  self = [super init];
  if (self) { _cmd = cmd; }
  return self;
}
@end
";
    let db = ws(
        Arc::new(bonsai_lang_objc::ObjCAdapter::new()),
        &[("Handler.m", src)],
    );
    let writes = first_nonempty_field_writes(&db);
    assert!(
        writes.iter().any(|w| w.target == "self.cmd"),
        "ObjC `_cmd = cmd` initializer must populate receiver_field_writes; got {writes:?}"
    );
}

#[test]
fn rust_struct_literal_constructor_populates() {
    let src = "
struct Handler { cmd: String }
impl Handler {
    fn new(cmd: String) -> Self { Self { cmd } }
}
";
    let db = ws(
        Arc::new(bonsai_lang_rust::RustAdapter::new()),
        &[("handler.rs", src)],
    );
    let writes = first_nonempty_field_writes(&db);
    assert!(
        writes.iter().any(|w| w.target == "self.cmd"),
        "Rust `Self {{ cmd }}` constructor must populate receiver_field_writes; got {writes:?}"
    );
}

#[test]
fn go_receiver_method_field_write_populates() {
    let src = "
package app
type Handler struct { cmd string }
func (h *Handler) Set(cmd string) { h.cmd = cmd }
";
    let db = ws(Arc::new(bonsai_lang_go::GoAdapter::new()), &[("handler.go", src)]);
    let writes = first_nonempty_field_writes(&db);
    assert!(
        writes.iter().any(|w| w.target == "h.cmd"),
        "Go receiver assignment `h.cmd = cmd` must populate receiver_field_writes; got {writes:?}"
    );
}

#[test]
fn solidity_constructor_state_field_populates() {
    let src = "
pragma solidity ^0.8.0;
contract Handler {
    address conn;
    constructor(address _conn) { conn = _conn; }
}
";
    let db = ws(
        Arc::new(bonsai_lang_solidity::SolidityAdapter::new()),
        &[("Handler.sol", src)],
    );
    let writes = first_nonempty_field_writes(&db);
    assert!(
        writes.iter().any(|w| w.target == "this.conn"),
        "Solidity constructor `conn = _conn` must populate receiver_field_writes; got {writes:?}"
    );
}

#[test]
fn lua_factory_self_field_populates() {
    let src = "
local Handler = {}
function Handler.new(cmd)
  local self = {}
  self.cmd = cmd
  return self
end
";
    let db = ws(
        Arc::new(bonsai_lang_lua::LuaAdapter::new()),
        &[("handler.lua", src)],
    );
    let writes = first_nonempty_field_writes(&db);
    assert!(
        writes.iter().any(|w| w.target == "self.cmd"),
        "Lua factory `self.cmd = cmd` must populate receiver_field_writes; got {writes:?}"
    );
}

#[test]
fn perl_bless_hash_constructor_populates() {
    let src = "
package Handler;
sub new {
  my ($class, $cmd) = @_;
  my $self = bless { cmd => $cmd }, $class;
  return $self;
}
1;
";
    let db = ws(
        Arc::new(bonsai_lang_perl::PerlAdapter::new()),
        &[("Handler.pm", src)],
    );
    let writes = first_nonempty_field_writes(&db);
    assert!(
        writes
            .iter()
            .any(|w| w.target.rsplit_once('.').is_some_and(|(_, field)| field == "cmd")),
        "Perl bless hash constructor must populate receiver_field_writes; got {writes:?}"
    );
}
