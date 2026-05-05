//! End-to-end P6 tests: adapter Lifecycle events →
//! `collect_lifecycle_transitions` → `requires_state` evaluation.

use bonsai_lang_api::LanguageRegistry;
use bonsai_security::{load_rulepack, match_rule_against_facts};
use bonsai_workspace::Workspace;
use std::path::{Path, PathBuf};
use std::sync::Arc;

fn ws_with<A: bonsai_lang_api::LanguageAdapter>(adapter: A, name: &str, source: &str) -> Workspace {
    let registry = Arc::new(LanguageRegistry::new());
    registry.register(Arc::new(adapter));
    let ws = Workspace::new(registry);
    ws.vfs().write(name.to_string(), Arc::<str>::from(source));
    for file in ws.vfs().all_files() {
        let _ = ws.db().decl_index(file);
        let _ = ws.db().import_index(file);
    }
    ws
}

fn write(path: &Path, content: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, content).unwrap();
}

fn c_ws(source: &str) -> Workspace {
    let registry = Arc::new(LanguageRegistry::new());
    registry.register(Arc::new(bonsai_lang_c::CAdapter::new()));
    let ws = Workspace::new(registry);
    ws.vfs().write("app.c".to_string(), Arc::<str>::from(source));
    for file in ws.vfs().all_files() {
        let _ = ws.db().decl_index(file);
        let _ = ws.db().import_index(file);
    }
    ws
}

fn cpp_ws(source: &str) -> Workspace {
    let registry = Arc::new(LanguageRegistry::new());
    registry.register(Arc::new(bonsai_lang_cpp::CppAdapter::new()));
    let ws = Workspace::new(registry);
    ws.vfs().write("app.cpp".to_string(), Arc::<str>::from(source));
    for file in ws.vfs().all_files() {
        let _ = ws.db().decl_index(file);
        let _ = ws.db().import_index(file);
    }
    ws
}

fn rust_ws(source: &str) -> Workspace {
    let registry = Arc::new(LanguageRegistry::new());
    registry.register(Arc::new(bonsai_lang_rust::RustAdapter::new()));
    let ws = Workspace::new(registry);
    ws.vfs().write("app.rs".to_string(), Arc::<str>::from(source));
    for file in ws.vfs().all_files() {
        let _ = ws.db().decl_index(file);
        let _ = ws.db().import_index(file);
    }
    ws
}

fn java_ws(source: &str) -> Workspace {
    let registry = Arc::new(LanguageRegistry::new());
    registry.register(Arc::new(bonsai_lang_java::JavaAdapter::new()));
    let ws = Workspace::new(registry);
    ws.vfs().write("App.java".to_string(), Arc::<str>::from(source));
    for file in ws.vfs().all_files() {
        let _ = ws.db().decl_index(file);
        let _ = ws.db().import_index(file);
    }
    ws
}

fn go_ws(source: &str) -> Workspace {
    let registry = Arc::new(LanguageRegistry::new());
    registry.register(Arc::new(bonsai_lang_go::GoAdapter::new()));
    let ws = Workspace::new(registry);
    ws.vfs().write("app.go".to_string(), Arc::<str>::from(source));
    for file in ws.vfs().all_files() {
        let _ = ws.db().decl_index(file);
        let _ = ws.db().import_index(file);
    }
    ws
}

fn python_ws(source: &str) -> Workspace {
    let registry = Arc::new(LanguageRegistry::new());
    registry.register(Arc::new(bonsai_lang_python::PythonAdapter::new()));
    let ws = Workspace::new(registry);
    ws.vfs().write("app.py".to_string(), Arc::<str>::from(source));
    for file in ws.vfs().all_files() {
        let _ = ws.db().decl_index(file);
        let _ = ws.db().import_index(file);
    }
    ws
}

// --------------------------------------------------------------- C
//
// `free(p); use(p);` — classic UAF. The adapter sees `free(p)` and
// emits `Lifecycle { name: "p", transition: "freed" }`. The rule
// requires `state: freed` for `p` at the `use` site.

#[test]
fn c_use_after_free_fires_with_requires_state() {
    let tmp = TempDir::new("c_uaf");
    write(
        &tmp.path().join("langs/c/sinks/uaf.yml"),
        r#"- id: c.test.use_after_free
  enabled: true
  language: c
  tag: use-after-free
  severity: high
  cwe: [CWE-416]
  match:
    kind: call
    callee:
      name: use
  constraints:
  - requires_state:
      name: p
      expected: freed
  description: "test rule"
  match_examples:
  - name: positive
    code: |
      void example(int *p) {
          free(p);
          use(p);
      }
"#,
    );
    let pack = load_rulepack(tmp.path()).expect("rulepack loads");
    let rule = pack.find_rule_by_id("c.test.use_after_free").expect("rule");

    let bad = c_ws(
        r#"
void example(int *p) {
    free(p);
    use(p);
}
"#,
    );
    let matches = match_rule_against_facts(&bad, rule);
    assert!(
        !matches.is_empty(),
        "C use-after-free with requires_state must fire when free precedes use; got {:?}",
        matches
    );

    let good = c_ws(
        r#"
void example(int *p) {
    use(p);
    free(p);
}
"#,
    );
    let matches = match_rule_against_facts(&good, rule);
    assert!(
        matches.is_empty(),
        "C use-before-free must NOT fire — no preceding lifecycle transition; got {:?}",
        matches
    );
}

#[test]
fn c_double_free_fires_with_requires_state() {
    let tmp = TempDir::new("c_double_free");
    write(
        &tmp.path().join("langs/c/sinks/double.yml"),
        r#"- id: c.test.double_free
  enabled: true
  language: c
  tag: double-free
  severity: high
  cwe: [CWE-415]
  match:
    kind: call
    callee:
      name: free
  constraints:
  - requires_state:
      name: p
      expected: freed
  description: "test rule"
  match_examples:
  - name: positive
    code: |
      void example(int *p) {
          free(p);
          free(p);
      }
"#,
    );
    let pack = load_rulepack(tmp.path()).expect("rulepack loads");
    let rule = pack.find_rule_by_id("c.test.double_free").expect("rule");

    let bad = c_ws(
        r#"
void example(int *p) {
    free(p);
    free(p);
}
"#,
    );
    let matches = match_rule_against_facts(&bad, rule);
    assert!(
        !matches.is_empty(),
        "C double-free must fire on second free after first marks the binding freed; got {:?}",
        matches
    );
}

#[test]
fn c_use_after_close_pthread_unlock() {
    let tmp = TempDir::new("c_unlock");
    write(
        &tmp.path().join("langs/c/sinks/unlock.yml"),
        r#"- id: c.test.use_after_unlock
  enabled: true
  language: c
  tag: lock-misuse
  severity: medium
  cwe: [CWE-832]
  match:
    kind: call
    callee:
      name: critical_section
  constraints:
  - requires_state:
      name: m
      expected: unlocked
  description: "test rule"
  match_examples:
  - name: positive
    code: |
      void example(pthread_mutex_t *m) {
          pthread_mutex_unlock(m);
          critical_section(m);
      }
"#,
    );
    let pack = load_rulepack(tmp.path()).expect("rulepack loads");
    let rule = pack.find_rule_by_id("c.test.use_after_unlock").expect("rule");

    let bad = c_ws(
        r#"
void example(pthread_mutex_t *m) {
    pthread_mutex_unlock(m);
    critical_section(m);
}
"#,
    );
    let matches = match_rule_against_facts(&bad, rule);
    assert!(
        !matches.is_empty(),
        "C use-after-unlock must fire after pthread_mutex_unlock(m); got {:?}",
        matches
    );
}

// --------------------------------------------------------------- C++
//
// `delete p; use(p);` — `delete_expression` is not a Call event so
// it doesn't drive the lifecycle lattice today. Instead we test
// `unique_ptr.release()` (which DOES emit a Call) and `std::move`.

#[test]
fn cpp_use_after_release_unique_ptr() {
    let tmp = TempDir::new("cpp_release");
    write(
        &tmp.path().join("langs/cpp/sinks/release.yml"),
        r#"- id: cpp.test.use_after_release
  enabled: true
  language: cpp
  tag: lifecycle
  severity: high
  cwe: [CWE-416]
  match:
    kind: call
    callee:
      name: read
  constraints:
  - requires_state:
      name: ptr
      expected: freed
  description: "test rule"
  match_examples:
  - name: positive
    code: |
      void example(std::unique_ptr<int> ptr) {
          ptr.release();
          read(ptr);
      }
"#,
    );
    let pack = load_rulepack(tmp.path()).expect("rulepack loads");
    let rule = pack.find_rule_by_id("cpp.test.use_after_release").expect("rule");

    let bad = cpp_ws(
        r#"
void example(std::unique_ptr<int> ptr) {
    ptr.release();
    read(ptr);
}
"#,
    );
    let matches = match_rule_against_facts(&bad, rule);
    assert!(
        !matches.is_empty(),
        "C++ use-after-release must fire on `read(ptr)` after `ptr.release()`; got {:?}",
        matches
    );
}

// --------------------------------------------------------------- Rust
//
// `drop(x); use(x);` — `drop` is the canonical Rust transition.
// Rust's borrow checker actually rejects this code at compile-time
// when types implement `Drop`, but the SAST tool still flags the
// pattern in cases where types are `Copy` or where `unsafe`
// shenanigans bypass the borrow checker (`Box::from_raw` etc.).

#[test]
fn rust_use_after_drop_fires_with_requires_state() {
    let tmp = TempDir::new("rust_drop");
    write(
        &tmp.path().join("langs/rust/sinks/use_after_drop.yml"),
        r#"- id: rust.test.use_after_drop
  enabled: true
  language: rust
  tag: lifecycle
  severity: high
  cwe: [CWE-672]
  match:
    kind: call
    callee:
      name: log
  constraints:
  - requires_state:
      name: handle
      expected: freed
  description: "test rule"
  match_examples:
  - name: positive
    code: |
      fn example(handle: usize) {
          drop(handle);
          log(handle);
      }
"#,
    );
    let pack = load_rulepack(tmp.path()).expect("rulepack loads");
    let rule = pack.find_rule_by_id("rust.test.use_after_drop").expect("rule");

    let bad = rust_ws(
        r#"
fn example(handle: usize) {
    drop(handle);
    log(handle);
}
"#,
    );
    let matches = match_rule_against_facts(&bad, rule);
    assert!(
        !matches.is_empty(),
        "Rust use-after-drop must fire on `log(handle)` after `drop(handle)`; got {:?}",
        matches
    );
}

// --------------------------------------------------------------- Java

#[test]
fn java_use_after_close_fires_with_requires_state() {
    let tmp = TempDir::new("java_close");
    write(
        &tmp.path().join("langs/java/sinks/close.yml"),
        r#"- id: java.test.use_after_close
  enabled: true
  language: java
  tag: use-after-close
  severity: medium
  cwe: [CWE-404]
  match:
    kind: call
    callee:
      name: read
  constraints:
  - requires_state:
      name: stream
      expected: closed
  description: "test rule"
  match_examples:
  - name: positive
    code: |
      class Foo {
          void example(Stream stream) {
              stream.close();
              stream.read();
          }
      }
"#,
    );
    let pack = load_rulepack(tmp.path()).expect("rulepack loads");
    let rule = pack.find_rule_by_id("java.test.use_after_close").expect("rule");

    let bad = java_ws(
        r#"
class Foo {
    void example(Stream stream) {
        stream.close();
        stream.read();
    }
}
"#,
    );
    let matches = match_rule_against_facts(&bad, rule);
    assert!(
        !matches.is_empty(),
        "Java use-after-close must fire on `stream.read()` after `stream.close()`; got {:?}",
        matches
    );
}

// --------------------------------------------------------------- Go

#[test]
fn go_use_after_close_fires_with_requires_state() {
    let tmp = TempDir::new("go_close");
    write(
        &tmp.path().join("langs/go/sinks/close.yml"),
        r#"- id: go.test.use_after_close
  enabled: true
  language: go
  tag: use-after-close
  severity: medium
  cwe: [CWE-404]
  match:
    kind: call
    callee:
      name: Read
  constraints:
  - requires_state:
      name: f
      expected: closed
  description: "test rule"
  match_examples:
  - name: positive
    code: |
      package main
      func example(f *File) {
          f.Close()
          f.Read()
      }
"#,
    );
    let pack = load_rulepack(tmp.path()).expect("rulepack loads");
    let rule = pack.find_rule_by_id("go.test.use_after_close").expect("rule");

    let bad = go_ws(
        r#"
package main
func example(f *File) {
    f.Close()
    f.Read()
}
"#,
    );
    let matches = match_rule_against_facts(&bad, rule);
    assert!(
        !matches.is_empty(),
        "Go use-after-close must fire on `f.Read()` after `f.Close()`; got {:?}",
        matches
    );
}

// --------------------------------------------------------------- Python

#[test]
fn python_use_after_close_fires_with_requires_state() {
    let tmp = TempDir::new("py_close");
    write(
        &tmp.path().join("langs/python/sinks/close.yml"),
        r#"- id: python.test.use_after_close
  enabled: true
  language: python
  tag: use-after-close
  severity: medium
  cwe: [CWE-404]
  match:
    kind: call
    callee:
      name: read
  constraints:
  - requires_state:
      name: f
      expected: closed
  description: "test rule"
  match_examples:
  - name: positive
    code: |
      def example(f):
          f.close()
          f.read()
"#,
    );
    let pack = load_rulepack(tmp.path()).expect("rulepack loads");
    let rule = pack.find_rule_by_id("python.test.use_after_close").expect("rule");

    let bad = python_ws(
        r#"
def example(f):
    f.close()
    f.read()
"#,
    );
    let matches = match_rule_against_facts(&bad, rule);
    assert!(
        !matches.is_empty(),
        "Python use-after-close must fire on `f.read()` after `f.close()`; got {:?}",
        matches
    );
}

// --------------------------------------------------------------- C#

#[test]
fn csharp_use_after_dispose_fires_with_requires_state() {
    let tmp = TempDir::new("cs_dispose");
    write(
        &tmp.path().join("langs/csharp/sinks/dispose.yml"),
        r#"- id: csharp.test.use_after_dispose
  enabled: true
  language: csharp
  tag: use-after-close
  severity: medium
  cwe: [CWE-404]
  match:
    kind: call
    callee:
      name: Read
  constraints:
  - requires_state:
      name: stream
      expected: freed
  description: "test rule"
  match_examples:
  - name: positive
    code: |
      class Foo {
          void example(Stream stream) {
              stream.Dispose();
              stream.Read();
          }
      }
"#,
    );
    let pack = load_rulepack(tmp.path()).expect("rulepack loads");
    let rule = pack
        .find_rule_by_id("csharp.test.use_after_dispose")
        .expect("rule");
    let bad = ws_with(
        bonsai_lang_csharp::CSharpAdapter::new(),
        "App.cs",
        r#"
class Foo {
    void example(Stream stream) {
        stream.Dispose();
        stream.Read();
    }
}
"#,
    );
    let matches = match_rule_against_facts(&bad, rule);
    assert!(
        !matches.is_empty(),
        "C# use-after-dispose must fire on `stream.Read()` after `stream.Dispose()`; got {:?}",
        matches
    );
}

// --------------------------------------------------------------- Kotlin

#[test]
fn kotlin_use_after_close_fires_with_requires_state() {
    let tmp = TempDir::new("kt_close");
    write(
        &tmp.path().join("langs/kotlin/sinks/close.yml"),
        r#"- id: kotlin.test.use_after_close
  enabled: true
  language: kotlin
  tag: use-after-close
  severity: medium
  cwe: [CWE-404]
  match:
    kind: call
    callee:
      name: read
  constraints:
  - requires_state:
      name: stream
      expected: closed
  description: "test rule"
  match_examples:
  - name: positive
    code: |
      class Foo {
          fun example(stream: Stream) {
              stream.close()
              stream.read()
          }
      }
"#,
    );
    let pack = load_rulepack(tmp.path()).expect("rulepack loads");
    let rule = pack.find_rule_by_id("kotlin.test.use_after_close").expect("rule");
    let bad = ws_with(
        bonsai_lang_kotlin::KotlinAdapter::new(),
        "App.kt",
        r#"
class Foo {
    fun example(stream: Stream) {
        stream.close()
        stream.read()
    }
}
"#,
    );
    let matches = match_rule_against_facts(&bad, rule);
    assert!(
        !matches.is_empty(),
        "Kotlin use-after-close must fire on `stream.read()` after `stream.close()`; got {:?}",
        matches
    );
}

// --------------------------------------------------------------- Scala

#[test]
fn scala_use_after_close_fires_with_requires_state() {
    let tmp = TempDir::new("scala_close");
    write(
        &tmp.path().join("langs/scala/sinks/close.yml"),
        r#"- id: scala.test.use_after_close
  enabled: true
  language: scala
  tag: use-after-close
  severity: medium
  cwe: [CWE-404]
  match:
    kind: call
    callee:
      name: read
  constraints:
  - requires_state:
      name: stream
      expected: closed
  description: "test rule"
  match_examples:
  - name: positive
    code: |
      class Foo {
        def example(stream: Stream): Unit = {
          stream.close()
          stream.read()
        }
      }
"#,
    );
    let pack = load_rulepack(tmp.path()).expect("rulepack loads");
    let rule = pack.find_rule_by_id("scala.test.use_after_close").expect("rule");
    let bad = ws_with(
        bonsai_lang_scala::ScalaAdapter::new(),
        "App.scala",
        r#"
class Foo {
  def example(stream: Stream): Unit = {
    stream.close()
    stream.read()
  }
}
"#,
    );
    let matches = match_rule_against_facts(&bad, rule);
    assert!(
        !matches.is_empty(),
        "Scala use-after-close must fire; got {:?}",
        matches
    );
}

// --------------------------------------------------------------- Swift

#[test]
fn swift_use_after_cancel_fires_with_requires_state() {
    let tmp = TempDir::new("swift_cancel");
    write(
        &tmp.path().join("langs/swift/sinks/cancel.yml"),
        r#"- id: swift.test.use_after_cancel
  enabled: true
  language: swift
  tag: use-after-cancel
  severity: medium
  cwe: [CWE-404]
  match:
    kind: call
    callee:
      name: result
  constraints:
  - requires_state:
      name: task
      expected: cancelled
  description: "test rule"
  match_examples:
  - name: positive
    code: |
      func example(task: Task) {
          task.cancel()
          task.result()
      }
"#,
    );
    let pack = load_rulepack(tmp.path()).expect("rulepack loads");
    let rule = pack.find_rule_by_id("swift.test.use_after_cancel").expect("rule");
    let bad = ws_with(
        bonsai_lang_swift::SwiftAdapter::new(),
        "App.swift",
        r#"
func example(task: Task) {
    task.cancel()
    task.result()
}
"#,
    );
    let matches = match_rule_against_facts(&bad, rule);
    assert!(
        !matches.is_empty(),
        "Swift use-after-cancel must fire; got {:?}",
        matches
    );
}

// --------------------------------------------------------------- Objective-C

#[test]
fn objc_use_after_release_fires_with_requires_state() {
    let tmp = TempDir::new("objc_release");
    write(
        &tmp.path().join("langs/objc/sinks/release.yml"),
        r#"- id: objc.test.use_after_release
  enabled: true
  language: objc
  tag: use-after-free
  severity: high
  cwe: [CWE-416]
  match:
    kind: call
    callee:
      name: read
  constraints:
  - requires_state:
      name: obj
      expected: freed
  description: "test rule"
  match_examples:
  - name: positive
    code: |
      void example(NSObject *obj) {
          [obj release];
          [obj read];
      }
"#,
    );
    let pack = load_rulepack(tmp.path()).expect("rulepack loads");
    let rule = pack.find_rule_by_id("objc.test.use_after_release").expect("rule");
    let bad = ws_with(
        bonsai_lang_objc::ObjCAdapter::new(),
        "App.m",
        r#"
void example(NSObject *obj) {
    [obj release];
    [obj read];
}
"#,
    );
    let matches = match_rule_against_facts(&bad, rule);
    assert!(
        !matches.is_empty(),
        "ObjC use-after-release must fire; got {:?}",
        matches
    );
}

// --------------------------------------------------------------- Dart

#[test]
fn dart_use_after_close_fires_with_requires_state() {
    let tmp = TempDir::new("dart_close");
    write(
        &tmp.path().join("langs/dart/sinks/close.yml"),
        r#"- id: dart.test.use_after_close
  enabled: true
  language: dart
  tag: use-after-close
  severity: medium
  cwe: [CWE-404]
  match:
    kind: call
    callee:
      name: read
  constraints:
  - requires_state:
      name: sink
      expected: closed
  description: "test rule"
  match_examples:
  - name: positive
    code: |
      void example(IOSink sink) {
        sink.close();
        sink.read();
      }
"#,
    );
    let pack = load_rulepack(tmp.path()).expect("rulepack loads");
    let rule = pack.find_rule_by_id("dart.test.use_after_close").expect("rule");
    let bad = ws_with(
        bonsai_lang_dart::DartAdapter::new(),
        "app.dart",
        r#"
void example(IOSink sink) {
  sink.close();
  sink.read();
}
"#,
    );
    let matches = match_rule_against_facts(&bad, rule);
    assert!(
        !matches.is_empty(),
        "Dart use-after-close must fire; got {:?}",
        matches
    );
}

// --------------------------------------------------------------- JavaScript

#[test]
fn javascript_use_after_destroy_fires_with_requires_state() {
    let tmp = TempDir::new("js_destroy");
    write(
        &tmp.path().join("langs/javascript/sinks/destroy.yml"),
        r#"- id: javascript.test.use_after_destroy
  enabled: true
  language: javascript
  tag: use-after-close
  severity: medium
  cwe: [CWE-404]
  match:
    kind: call
    callee:
      name: write
  constraints:
  - requires_state:
      name: stream
      expected: freed
  description: "test rule"
  match_examples:
  - name: positive
    code: |
      function example(stream) {
        stream.destroy();
        stream.write();
      }
"#,
    );
    let pack = load_rulepack(tmp.path()).expect("rulepack loads");
    let rule = pack
        .find_rule_by_id("javascript.test.use_after_destroy")
        .expect("rule");
    let bad = ws_with(
        bonsai_lang_javascript::JavaScriptAdapter::new(),
        "app.js",
        r#"
function example(stream) {
  stream.destroy();
  stream.write();
}
"#,
    );
    let matches = match_rule_against_facts(&bad, rule);
    assert!(
        !matches.is_empty(),
        "JavaScript use-after-destroy must fire; got {:?}",
        matches
    );
}

// --------------------------------------------------------------- TypeScript

#[test]
fn typescript_use_after_abort_fires_with_requires_state() {
    let tmp = TempDir::new("ts_abort");
    write(
        &tmp.path().join("langs/typescript/sinks/abort.yml"),
        r#"- id: typescript.test.use_after_abort
  enabled: true
  language: typescript
  tag: use-after-cancel
  severity: medium
  cwe: [CWE-404]
  match:
    kind: call
    callee:
      name: poll
  constraints:
  - requires_state:
      name: ctrl
      expected: cancelled
  description: "test rule"
  match_examples:
  - name: positive
    code: |
      function example(ctrl: AbortController) {
        ctrl.abort();
        ctrl.poll();
      }
"#,
    );
    let pack = load_rulepack(tmp.path()).expect("rulepack loads");
    let rule = pack
        .find_rule_by_id("typescript.test.use_after_abort")
        .expect("rule");
    let bad = ws_with(
        bonsai_lang_typescript::TypeScriptAdapter::new(),
        "app.ts",
        r#"
function example(ctrl: AbortController) {
  ctrl.abort();
  ctrl.poll();
}
"#,
    );
    let matches = match_rule_against_facts(&bad, rule);
    assert!(
        !matches.is_empty(),
        "TypeScript use-after-abort must fire; got {:?}",
        matches
    );
}

// --------------------------------------------------------------- Ruby

#[test]
fn ruby_use_after_close_fires_with_requires_state() {
    let tmp = TempDir::new("ruby_close");
    write(
        &tmp.path().join("langs/ruby/sinks/close.yml"),
        r#"- id: ruby.test.use_after_close
  enabled: true
  language: ruby
  tag: use-after-close
  severity: medium
  cwe: [CWE-404]
  match:
    kind: call
    callee:
      name: read
  constraints:
  - requires_state:
      name: f
      expected: closed
  description: "test rule"
  match_examples:
  - name: positive
    code: |
      def example(f)
        f.close
        f.read
      end
"#,
    );
    let pack = load_rulepack(tmp.path()).expect("rulepack loads");
    let rule = pack.find_rule_by_id("ruby.test.use_after_close").expect("rule");
    let bad = ws_with(
        bonsai_lang_ruby::RubyAdapter::new(),
        "app.rb",
        r#"
def example(f)
  f.close
  f.read
end
"#,
    );
    let matches = match_rule_against_facts(&bad, rule);
    assert!(
        !matches.is_empty(),
        "Ruby use-after-close must fire; got {:?}",
        matches
    );
}

// --------------------------------------------------------------- PHP

#[test]
fn php_use_after_fclose_fires_with_requires_state() {
    let tmp = TempDir::new("php_fclose");
    write(
        &tmp.path().join("langs/php/sinks/fclose.yml"),
        r#"- id: php.test.use_after_fclose
  enabled: true
  language: php
  tag: use-after-close
  severity: medium
  cwe: [CWE-404]
  match:
    kind: call
    callee:
      name: fread
  constraints:
  - requires_state:
      name: f
      expected: closed
  description: "test rule"
  match_examples:
  - name: positive
    code: |
      <?php
      function example($f) {
          fclose($f);
          fread($f);
      }
"#,
    );
    let pack = load_rulepack(tmp.path()).expect("rulepack loads");
    let rule = pack.find_rule_by_id("php.test.use_after_fclose").expect("rule");
    let bad = ws_with(
        bonsai_lang_php::PhpAdapter::new(),
        "app.php",
        r#"<?php
function example($f) {
    fclose($f);
    fread($f);
}
"#,
    );
    let matches = match_rule_against_facts(&bad, rule);
    assert!(
        !matches.is_empty(),
        "PHP use-after-fclose must fire; got {:?}",
        matches
    );
}

// --------------------------------------------------------------- Perl

#[test]
fn perl_use_after_close_fires_with_requires_state() {
    let tmp = TempDir::new("perl_close");
    write(
        &tmp.path().join("langs/perl/sinks/close.yml"),
        r#"- id: perl.test.use_after_close
  enabled: true
  language: perl
  tag: use-after-close
  severity: medium
  cwe: [CWE-404]
  match:
    kind: call
    callee:
      name: read
  constraints:
  - requires_state:
      name: fh
      expected: closed
  description: "test rule"
  match_examples:
  - name: positive
    code: |
      sub example {
          my $fh = shift;
          close($fh);
          read($fh);
      }
"#,
    );
    let pack = load_rulepack(tmp.path()).expect("rulepack loads");
    let rule = pack.find_rule_by_id("perl.test.use_after_close").expect("rule");
    let bad = ws_with(
        bonsai_lang_perl::PerlAdapter::new(),
        "app.pl",
        r#"
sub example {
    my $fh = shift;
    close($fh);
    read($fh);
}
"#,
    );
    let matches = match_rule_against_facts(&bad, rule);
    assert!(
        !matches.is_empty(),
        "Perl use-after-close must fire; got {:?}",
        matches
    );
}

// --------------------------------------------------------------- Lua

#[test]
fn lua_use_after_close_fires_with_requires_state() {
    let tmp = TempDir::new("lua_close");
    write(
        &tmp.path().join("langs/lua/sinks/close.yml"),
        r#"- id: lua.test.use_after_close
  enabled: true
  language: lua
  tag: use-after-close
  severity: medium
  cwe: [CWE-404]
  match:
    kind: call
    callee:
      name: read
  constraints:
  - requires_state:
      name: f
      expected: closed
  description: "test rule"
  match_examples:
  - name: positive
    code: |
      function example(f)
          f:close()
          f:read()
      end
"#,
    );
    let pack = load_rulepack(tmp.path()).expect("rulepack loads");
    let rule = pack.find_rule_by_id("lua.test.use_after_close").expect("rule");
    let bad = ws_with(
        bonsai_lang_lua::LuaAdapter::new(),
        "app.lua",
        r#"
function example(f)
    f:close()
    f:read()
end
"#,
    );
    let matches = match_rule_against_facts(&bad, rule);
    assert!(
        !matches.is_empty(),
        "Lua use-after-close must fire; got {:?}",
        matches
    );
}

// --------------------------------------------------------------- Elixir

#[test]
fn elixir_use_after_stop_fires_with_requires_state() {
    let tmp = TempDir::new("elx_stop");
    write(
        &tmp.path().join("langs/elixir/sinks/stop.yml"),
        r#"- id: elixir.test.use_after_stop
  enabled: true
  language: elixir
  tag: use-after-close
  severity: medium
  cwe: [CWE-404]
  match:
    kind: call
    callee:
      name: send
  constraints:
  - requires_state:
      name: server
      expected: cancelled
  description: "test rule"
  match_examples:
  - name: positive
    code: |
      defmodule Foo do
        def example(server) do
          :gen_server.stop(server)
          send(server, :ping)
        end
      end
"#,
    );
    let pack = load_rulepack(tmp.path()).expect("rulepack loads");
    let rule = pack.find_rule_by_id("elixir.test.use_after_stop").expect("rule");
    let bad = ws_with(
        bonsai_lang_elixir::ElixirAdapter::new(),
        "app.ex",
        r#"
defmodule Foo do
  def example(server) do
    :gen_server.stop(server)
    send(server, :ping)
  end
end
"#,
    );
    let matches = match_rule_against_facts(&bad, rule);
    assert!(
        !matches.is_empty(),
        "Elixir use-after-stop must fire; got {:?}",
        matches
    );
}

// --------------------------------------------------------------- Erlang

#[test]
fn erlang_use_after_stop_fires_with_requires_state() {
    let tmp = TempDir::new("erl_stop");
    write(
        &tmp.path().join("langs/erlang/sinks/stop.yml"),
        r#"- id: erlang.test.use_after_stop
  enabled: true
  language: erlang
  tag: use-after-close
  severity: medium
  cwe: [CWE-404]
  match:
    kind: call
    callee:
      name: send
  constraints:
  - requires_state:
      name: Server
      expected: cancelled
  description: "test rule"
  match_examples:
  - name: positive
    code: |
      example(Server) ->
          gen_server:stop(Server),
          send(Server, ping).
"#,
    );
    let pack = load_rulepack(tmp.path()).expect("rulepack loads");
    let rule = pack.find_rule_by_id("erlang.test.use_after_stop").expect("rule");
    let bad = ws_with(
        bonsai_lang_erlang::ErlangAdapter::new(),
        "app.erl",
        r#"
example(Server) ->
    gen_server:stop(Server),
    send(Server, ping).
"#,
    );
    let matches = match_rule_against_facts(&bad, rule);
    assert!(
        !matches.is_empty(),
        "Erlang use-after-stop must fire; got {:?}",
        matches
    );
}

// --------------------------------------------------------------- Solidity

#[test]
fn solidity_use_after_selfdestruct_fires_with_requires_state() {
    let tmp = TempDir::new("sol_selfdestruct");
    write(
        &tmp.path().join("langs/solidity/sinks/selfdestruct.yml"),
        r#"- id: solidity.test.use_after_selfdestruct
  enabled: true
  language: solidity
  tag: use-after-free
  severity: high
  cwe: [CWE-416]
  match:
    kind: call
    callee:
      name: emit_event
  constraints:
  - requires_state:
      name: target
      expected: freed
  description: "test rule"
  match_examples:
  - name: positive
    code: |
      contract Foo {
          function example(address target) public {
              selfdestruct(target);
              emit_event(target);
          }
      }
"#,
    );
    let pack = load_rulepack(tmp.path()).expect("rulepack loads");
    let rule = pack
        .find_rule_by_id("solidity.test.use_after_selfdestruct")
        .expect("rule");
    let bad = ws_with(
        bonsai_lang_solidity::SolidityAdapter::new(),
        "App.sol",
        r#"
contract Foo {
    function example(address target) public {
        selfdestruct(target);
        emit_event(target);
    }
}
"#,
    );
    let matches = match_rule_against_facts(&bad, rule);
    assert!(
        !matches.is_empty(),
        "Solidity use-after-selfdestruct must fire; got {:?}",
        matches
    );
}

// --------------------------------------------------------------- helpers

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(tag: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "bonsai-lifecycle-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&path).unwrap();
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}
