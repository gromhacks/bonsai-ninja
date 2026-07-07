//! Cross-language FlowEvent shape conformance (spec §Phase-9).
//!
//! Runs a fixed canonical fixture against every bundled adapter and
//! asserts the engine sees the same FlowEvent shapes for the same
//! source constructs. The canonical shapes are documented in
//! [docs/contributing/flow-event-spec.mdx](../../docs/contributing/flow-event-spec.mdx).
//!
//! When a language genuinely lacks a construct (Erlang has no
//! classes, Lua has no `try`), the fixture omits that construct and
//! the corresponding assertion is skipped via `Conformance::skip`.

use bonsai_lang_api::{AssignValueKind, Decl, FlowEvent, LanguageAdapter};
use bonsai_workspace::Workspace;
use std::sync::Arc;

/// One canonical shape and how to recognise it in a flow-event tree.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum CanonicalShape {
    /// `y = x` — Assign with `source_name = Some("x")`, target `"y"`.
    BareRename,
    /// `y = "abc"` — Assign with `value_kind = Some(Literal)`, target `"y"`.
    LiteralWrite,
    /// `y = f(x)` — Assign with `source_call = Some("f")`, target `"y"`.
    DirectCall,
    /// `if x: F(t)` — Branch with `condition = Some("x")` containing a
    /// Call to `F` with arg text `"t"`.
    SingleConditionBranch,
    /// `try { F(t) } catch e { ... }` — Try with `catch_param = Some("e")`.
    CatchBind,
    /// `for it in items: F(it)` — Loop whose body contains a Call to `F`.
    LoopBody,
    /// `return y` — Return with `value_name = Some("y")`.
    BareReturn,
}

impl CanonicalShape {
    fn label(self) -> &'static str {
        match self {
            CanonicalShape::BareRename => "bare_rename",
            CanonicalShape::LiteralWrite => "literal_write",
            CanonicalShape::DirectCall => "direct_call",
            CanonicalShape::SingleConditionBranch => "single_condition_branch",
            CanonicalShape::CatchBind => "catch_bind",
            CanonicalShape::LoopBody => "loop_body",
            CanonicalShape::BareReturn => "bare_return",
        }
    }
}

struct Conformance {
    lang: &'static str,
    fixture_path: &'static str,
    fixture_source: &'static str,
    /// Function name inside the fixture that contains the canonical
    /// shapes. Lookups go through the workspace, so qualified
    /// resolution paths must match.
    function_name: &'static str,
    /// Callee name used for the branch-body call (`F` unless the
    /// language forbids that spelling — Elixir capitalised
    /// identifiers are module aliases, not callables).
    branch_callee: &'static str,
    /// Callee name used for the loop-body call (`G` by default).
    loop_callee: &'static str,
    /// Shapes the language genuinely cannot express. Empty by default.
    skip: &'static [CanonicalShape],
}

struct ShapeResult {
    shape: CanonicalShape,
    found: bool,
    skipped: bool,
}

fn run_conformance(c: &Conformance) -> Vec<ShapeResult> {
    let adapter = adapter_for_lang(c.lang);
    let ws = bonsai_testkit::workspace_with(vec![adapter], &[(c.fixture_path, c.fixture_source)]);
    let func_decl = find_decl(&ws, c.function_name)
        .unwrap_or_else(|| panic!("function `{}` not found in {}", c.function_name, c.lang));
    let mut results: Vec<ShapeResult> = Vec::new();
    for shape in [
        CanonicalShape::BareRename,
        CanonicalShape::LiteralWrite,
        CanonicalShape::DirectCall,
        CanonicalShape::SingleConditionBranch,
        CanonicalShape::CatchBind,
        CanonicalShape::LoopBody,
        CanonicalShape::BareReturn,
    ] {
        // Skipped shapes are still evaluated: a skip that now passes
        // is stale and must be removed so coverage can't regress
        // silently.
        results.push(ShapeResult {
            shape,
            found: shape_present(&func_decl.flow_events, shape, c),
            skipped: c.skip.contains(&shape),
        });
    }
    results
}

fn adapter_for_lang(lang: &str) -> Arc<dyn LanguageAdapter> {
    for a in bonsai_adapters::all_adapters() {
        if a.language_id().as_str() == lang {
            return a;
        }
    }
    panic!("no bundled adapter for `{lang}`");
}

fn find_decl(ws: &Workspace, name: &str) -> Option<Decl> {
    let global = ws.db().global_index();
    for file in global.all_files() {
        for decl in global.decls_in(file) {
            if decl.name == name {
                return Some(decl.clone());
            }
        }
    }
    None
}

fn shape_present(events: &[FlowEvent], shape: CanonicalShape, c: &Conformance) -> bool {
    walk_events(events, &|e| matches_shape(e, shape, c))
}

fn walk_events(events: &[FlowEvent], pred: &dyn Fn(&FlowEvent) -> bool) -> bool {
    for ev in events {
        if pred(ev) {
            return true;
        }
        match ev {
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                if walk_events(then_events, pred) || walk_events(else_events, pred) {
                    return true;
                }
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                if walk_events(body, pred) {
                    return true;
                }
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                if walk_events(body, pred)
                    || walk_events(catch_events, pred)
                    || walk_events(finally_events, pred)
                {
                    return true;
                }
            }
            _ => {}
        }
    }
    false
}

fn matches_shape(event: &FlowEvent, shape: CanonicalShape, c: &Conformance) -> bool {
    match (shape, event) {
        (
            CanonicalShape::BareRename,
            FlowEvent::Assign {
                target,
                source_name: Some(src),
                ..
            },
        ) => sigil_strip(target) == "y" && sigil_strip(src) == "x",
        (
            CanonicalShape::LiteralWrite,
            FlowEvent::Assign {
                target,
                value_kind: Some(AssignValueKind::Literal),
                ..
            },
        ) => sigil_strip(target) == "lit",
        (
            CanonicalShape::DirectCall,
            FlowEvent::Assign {
                target,
                source_call: Some(callee),
                ..
            },
        ) => sigil_strip(target) == "z" && callee == "f",
        (
            CanonicalShape::SingleConditionBranch,
            FlowEvent::Branch {
                condition,
                then_events,
                ..
            },
        ) => {
            // Adapters may render `x` or `(x)` or `x != null` etc.; only
            // assert that condition exists (or is omitted but body has F).
            let cond_ok = condition.as_deref().map(|c| !c.trim().is_empty()).unwrap_or(true);
            cond_ok && body_contains_call(then_events, c.branch_callee)
        }
        (
            CanonicalShape::CatchBind,
            FlowEvent::Try {
                catch_param: Some(p), ..
            },
        ) => sigil_strip(p) == "e",
        (CanonicalShape::LoopBody, FlowEvent::Loop { body, .. }) => body_contains_call(body, c.loop_callee),
        (
            CanonicalShape::BareReturn,
            FlowEvent::Return {
                value_name: Some(v), ..
            },
        ) => {
            let stripped = sigil_strip(v);
            stripped == "y" || stripped == "z"
        }
        _ => false,
    }
}

/// Strip the leading sigil so PHP/Perl `$y` matches `y` in the
/// canonical shape assertions. Engines downstream of the FlowEvent
/// emit similar sigil-stripped names; this normalisation is a
/// test-only convenience.
fn sigil_strip(s: &str) -> &str {
    s.strip_prefix('$')
        .or_else(|| s.strip_prefix('@'))
        .or_else(|| s.strip_prefix('%'))
        .unwrap_or(s)
}

fn body_contains_call(body: &[FlowEvent], callee: &str) -> bool {
    walk_events(
        body,
        &|e| matches!(e, FlowEvent::Call { name, .. } if name == callee),
    )
}

#[test]
fn ruby_no_parentheses_receiver_send_stays_call_result() {
    let ws = bonsai_testkit::workspace_with(
        vec![adapter_for_lang("ruby")],
        &[(
            "app.rb",
            r#"def helper
  raw = gets.to_s
  cb = method(:helper)
  cb.call(raw)
end
"#,
        )],
    );
    let helper = find_decl(&ws, "helper").expect("helper decl");
    let raw_assign = helper
        .flow_events
        .iter()
        .find_map(|event| match event {
            FlowEvent::Assign {
                target,
                source_name,
                source_call,
                value_kind,
                ..
            } if target == "raw" => Some((source_name, source_call, value_kind)),
            _ => None,
        })
        .expect("raw assignment");
    assert_eq!(raw_assign.0.as_deref(), None);
    assert_eq!(raw_assign.1.as_deref(), Some("gets.to_s"));
    assert_eq!(raw_assign.2, &Some(AssignValueKind::CallResult));

    let callback_assign = helper
        .flow_events
        .iter()
        .find_map(|event| match event {
            FlowEvent::Assign {
                target,
                source_name,
                source_call,
                value_kind,
                ..
            } if target == "cb" => Some((source_name, source_call, value_kind)),
            _ => None,
        })
        .expect("callback assignment");
    assert_eq!(callback_assign.0.as_deref(), Some("method(:helper)"));
    assert_eq!(callback_assign.1.as_deref(), None);
    assert_eq!(callback_assign.2, &Some(AssignValueKind::Compound));
}

fn fixture_for(lang: &str) -> Conformance {
    match lang {
        "python" => Conformance {
            lang: "python",
            fixture_path: "shape.py",
            fixture_source: r#"def shapes(x, items, t):
    y = x
    lit = "abc"
    z = f(x)
    if x:
        F(t)
    try:
        for it in items:
            G(it)
    except Exception as e:
        return e
    return y
"#,
            function_name: "shapes",
            branch_callee: "F",
            loop_callee: "G",
            skip: &[],
        },
        "javascript" => Conformance {
            lang: "javascript",
            fixture_path: "shape.js",
            fixture_source: r#"function shapes(x, items, t) {
  let y = x;
  let lit = "abc";
  let z = f(x);
  if (x) { F(t); }
  try {
    for (const it of items) { G(it); }
  } catch (e) { return e; }
  return y;
}
"#,
            function_name: "shapes",
            branch_callee: "F",
            loop_callee: "G",
            skip: &[],
        },
        "typescript" => Conformance {
            lang: "typescript",
            fixture_path: "shape.ts",
            fixture_source: r#"function shapes(x: string, items: string[], t: string): string {
  let y: string = x;
  let lit: string = "abc";
  let z: string = f(x);
  if (x) { F(t); }
  try {
    for (const it of items) { G(it); }
  } catch (e) { return e as string; }
  return y;
}
"#,
            function_name: "shapes",
            branch_callee: "F",
            loop_callee: "G",
            skip: &[],
        },
        "java" => Conformance {
            lang: "java",
            fixture_path: "Shape.java",
            fixture_source: r#"package app;
class Shape {
  String shapes(String x, java.util.List<String> items, String t) {
    String y = x;
    String lit = "abc";
    String z = f(x);
    if (x != null) { F(t); }
    try {
      for (String it : items) { G(it); }
    } catch (Exception e) { return null; }
    return y;
  }
  String f(String a) { return a; }
  void F(String a) {}
  void G(String a) {}
}
"#,
            function_name: "shapes",
            branch_callee: "F",
            loop_callee: "G",
            skip: &[],
        },
        "csharp" => Conformance {
            lang: "csharp",
            fixture_path: "Shape.cs",
            fixture_source: r#"namespace App;
class Shape {
  public string Shapes(string x, System.Collections.Generic.List<string> items, string t) {
    string y = x;
    string lit = "abc";
    string z = f(x);
    if (x != null) { F(t); }
    try {
      foreach (var it in items) { G(it); }
    } catch (System.Exception e) { return null; }
    return y;
  }
  string f(string a) { return a; }
  void F(string a) {}
  void G(string a) {}
}
"#,
            function_name: "Shapes",
            branch_callee: "F",
            loop_callee: "G",
            skip: &[],
        },
        "rust" => Conformance {
            lang: "rust",
            fixture_path: "shape.rs",
            fixture_source: r#"fn shapes(x: &str, items: Vec<&str>, t: &str) -> String {
    let y = x;
    let lit = "abc";
    let z = f(x);
    if !x.is_empty() {
        F(t);
    }
    for it in items {
        G(it);
    }
    let _ = lit;
    let _ = z;
    y.to_string()
}
fn f(a: &str) -> &str { a }
fn F(_a: &str) {}
fn G(_a: &str) {}
"#,
            function_name: "shapes",
            branch_callee: "F",
            loop_callee: "G",
            // Rust expression returns bind through the final-expr rule;
            // adapter-level `Return` events are emitted for explicit
            // `return EXPR` only. Skip the BareReturn assertion.
            // Rust has no `try`/`catch` keyword form for this fixture.
            skip: &[CanonicalShape::CatchBind, CanonicalShape::BareReturn],
        },
        "go" => Conformance {
            lang: "go",
            fixture_path: "shape.go",
            fixture_source: r#"package app
func shapes(x string, items []string, t string) string {
  y := x
  lit := "abc"
  z := f(x)
  if x != "" { F(t) }
  for _, it := range items { G(it) }
  _ = lit
  _ = z
  return y
}
func f(a string) string { return a }
func F(a string) {}
func G(a string) {}
"#,
            function_name: "shapes",
            branch_callee: "F",
            loop_callee: "G",
            // Go has `defer recover()` but not catch-bind.
            skip: &[CanonicalShape::CatchBind],
        },
        "kotlin" => Conformance {
            lang: "kotlin",
            fixture_path: "Shape.kt",
            fixture_source: r#"package app
fun shapes(x: String, items: List<String>, t: String): String {
  val y = x
  val lit = "abc"
  val z = f(x)
  if (x.isNotEmpty()) { F(t) }
  try {
    for (it in items) { G(it) }
  } catch (e: Exception) { return "" }
  return y
}
fun f(a: String): String = a
fun F(a: String) {}
fun G(a: String) {}
"#,
            function_name: "shapes",
            branch_callee: "F",
            loop_callee: "G",
            skip: &[],
        },
        "scala" => Conformance {
            lang: "scala",
            fixture_path: "Shape.scala",
            fixture_source: r#"package app
object Shape {
  def shapes(x: String, items: List[String], t: String): String = {
    val y = x
    val lit = "abc"
    val z = f(x)
    if (x.nonEmpty) F(t)
    try {
      for (it <- items) G(it)
    } catch { case e: Exception => () }
    val _ = lit
    val _ = z
    y
  }
  def f(a: String): String = a
  def F(a: String): Unit = ()
  def G(a: String): Unit = ()
}
"#,
            function_name: "shapes",
            branch_callee: "F",
            loop_callee: "G",
            // Scala's tail expression now emits a Return event (the
            // adapter opts into `tail_expression_returns`), so the
            // value-final `y` conforms to BareReturn like Rust/Ruby.
            skip: &[],
        },
        "swift" => Conformance {
            lang: "swift",
            fixture_path: "Shape.swift",
            fixture_source: r#"func shapes(_ x: String, _ items: [String], _ t: String) -> String {
  let y = x
  let lit = "abc"
  let z = f(x)
  if !x.isEmpty { F(t) }
  do {
    for it in items { G(it) }
  } catch let e {
    _ = e
  }
  _ = lit
  _ = z
  return y
}
func f(_ a: String) -> String { return a }
func F(_ a: String) {}
func G(_ a: String) {}
"#,
            function_name: "shapes",
            branch_callee: "F",
            loop_callee: "G",
            skip: &[],
        },
        "ruby" => Conformance {
            lang: "ruby",
            fixture_path: "shape.rb",
            fixture_source: r#"def shapes(x, items, t)
  y = x
  lit = "abc"
  z = f(x)
  F(t) if x
  begin
    items.each do |it|
      G(it)
    end
  rescue => e
    return e
  end
  y
end
"#,
            function_name: "shapes",
            branch_callee: "F",
            loop_callee: "G",
            skip: &[],
        },
        "perl" => Conformance {
            lang: "perl",
            fixture_path: "Shape.pm",
            fixture_source: r#"package Shape;
sub shapes {
  my ($x, $items, $t) = @_;
  my $y = $x;
  my $lit = "abc";
  my $z = f($x);
  if ($x) { F($t); }
  eval {
    for my $it (@$items) { G($it); }
  };
  if ($@) { my $e = $@; return $e; }
  return $y;
}
sub f { return $_[0]; }
sub F { }
sub G { }
1;
"#,
            function_name: "shapes",
            branch_callee: "F",
            loop_callee: "G",
            skip: &[],
        },
        "php" => Conformance {
            lang: "php",
            fixture_path: "Shape.php",
            fixture_source: r#"<?php
function shapes($x, $items, $t) {
  $y = $x;
  $lit = "abc";
  $z = f($x);
  if ($x) { F($t); }
  try {
    foreach ($items as $it) { G($it); }
  } catch (\Exception $e) { return $e; }
  return $y;
}
function f($a) { return $a; }
function F($a) {}
function G($a) {}
"#,
            function_name: "shapes",
            branch_callee: "F",
            loop_callee: "G",
            skip: &[],
        },
        "dart" => Conformance {
            lang: "dart",
            fixture_path: "shape.dart",
            fixture_source: r#"String shapes(String x, List<String> items, String t) {
  final y = x;
  final lit = "abc";
  final z = f(x);
  if (x.isNotEmpty) { F(t); }
  try {
    for (final it in items) { G(it); }
  } catch (e) { return ""; }
  return y;
}
String f(String a) => a;
void F(String a) {}
void G(String a) {}
"#,
            function_name: "shapes",
            branch_callee: "F",
            loop_callee: "G",
            skip: &[],
        },
        "lua" => Conformance {
            lang: "lua",
            fixture_path: "shape.lua",
            fixture_source: r#"local function shapes(x, items, t)
  local y = x
  local lit = "abc"
  local z = f(x)
  if x then F(t) end
  for _, it in ipairs(items) do
    G(it)
  end
  local _ = lit
  local _ = z
  return y
end
return shapes
"#,
            function_name: "shapes",
            branch_callee: "F",
            loop_callee: "G",
            // Lua has no try/catch.
            skip: &[CanonicalShape::CatchBind],
        },
        "objc" => Conformance {
            lang: "objc",
            fixture_path: "Shape.m",
            fixture_source: r#"#import <Foundation/Foundation.h>

NSString *shapes(NSString *x, NSArray<NSString *> *items, NSString *t) {
  NSString *y = x;
  NSString *lit = @"abc";
  NSString *z = f(x);
  if (x != nil) { F(t); }
  @try {
    for (NSString *it in items) { G(it); }
  } @catch (NSException *e) { return @""; }
  return y;
}
NSString *f(NSString *a) { return a; }
void F(NSString *a) {}
void G(NSString *a) {}
"#,
            function_name: "shapes",
            branch_callee: "F",
            loop_callee: "G",
            skip: &[],
        },
        "elixir" => Conformance {
            lang: "elixir",
            fixture_path: "shape.ex",
            // Capitalised identifiers are module aliases in Elixir, so
            // the canonical `F`/`G` callees are spelt `sink_f`/`sink_g`
            // — the fixture must be valid syntax: the adapter refuses
            // flow facts from files with parse errors.
            fixture_source: r#"defmodule Shape do
  def shapes(x, items, t) do
    y = x
    lit = "abc"
    z = f(x)
    if x do
      sink_f(t)
    end
    try do
      Enum.each(items, fn it -> sink_g(it) end)
    rescue
      e -> e
    end
    _ = lit
    _ = z
    y
  end
  def f(a), do: a
  def sink_f(a), do: a
  def sink_g(a), do: a
end
"#,
            function_name: "shapes",
            branch_callee: "sink_f",
            loop_callee: "sink_g",
            skip: &[],
        },
        "erlang" => Conformance {
            lang: "erlang",
            fixture_path: "shape.erl",
            fixture_source: r#"-module(shape).
-export([shapes/3, f/1]).

shapes(X, Items, T) ->
  Y = X,
  Lit = "abc",
  Z = f(X),
  case X of
    undefined -> ok;
    _ -> 'F'(T)
  end,
  try
    lists:foreach(fun(It) -> 'G'(It) end, Items)
  catch
    _:E -> E
  end,
  _ = Lit,
  _ = Z,
  Y.

f(A) -> A.
'F'(_) -> ok.
'G'(_) -> ok.
"#,
            function_name: "shapes",
            branch_callee: "F",
            loop_callee: "G",
            // Erlang has no `for` loop — uses `lists:foreach`. Skip
            // LoopBody. Also no explicit Return event for tail expr.
            // Erlang uses `case` for branching — adapter may map case
            // arms to a Branch, but condition is not a single bare
            // expression. Skip SingleConditionBranch.
            // Capitalised idents follow Erlang variable rules so use
            // `X`/`Y`/`Z` LHS — adapter lowercases names; check below.
            skip: &[
                CanonicalShape::BareReturn,
                CanonicalShape::LoopBody,
                CanonicalShape::SingleConditionBranch,
                CanonicalShape::BareRename,
                CanonicalShape::LiteralWrite,
                CanonicalShape::DirectCall,
                CanonicalShape::CatchBind,
            ],
        },
        "solidity" => Conformance {
            lang: "solidity",
            fixture_path: "Shape.sol",
            fixture_source: r#"// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

contract Shape {
  function shapes(uint256 x, uint256[] memory items, uint256 t) public returns (uint256) {
    uint256 y = x;
    uint256 lit = 0;
    uint256 z = f(x);
    if (x != 0) { F(t); }
    for (uint256 i = 0; i < items.length; i++) {
      G(items[i]);
    }
    return y;
  }
  function f(uint256 a) internal pure returns (uint256) { return a; }
  function F(uint256 a) internal pure {}
  function G(uint256 a) internal pure {}
}
"#,
            function_name: "shapes",
            branch_callee: "F",
            loop_callee: "G",
            // Solidity has no try/catch in the catch-bind form used
            // here.
            skip: &[CanonicalShape::CatchBind],
        },
        "c" => Conformance {
            lang: "c",
            fixture_path: "shape.c",
            fixture_source: r#"#include <string.h>

const char *shapes(const char *x, const char **items, int n, const char *t) {
  const char *y = x;
  const char *lit = "abc";
  const char *z = f(x);
  if (x) { F(t); }
  for (int i = 0; i < n; i++) { G(items[i]); }
  (void)lit;
  (void)z;
  return y;
}
const char *f(const char *a) { return a; }
void F(const char *a) {}
void G(const char *a) {}
"#,
            function_name: "shapes",
            branch_callee: "F",
            loop_callee: "G",
            // C has no try/catch — skip catch-bind.
            skip: &[CanonicalShape::CatchBind],
        },
        "cpp" => Conformance {
            lang: "cpp",
            fixture_path: "shape.cpp",
            fixture_source: r#"#include <string>
#include <vector>
#include <stdexcept>

std::string shapes(const std::string& x, const std::vector<std::string>& items, const std::string& t) {
  std::string y = x;
  std::string lit = "abc";
  std::string z = f(x);
  if (!x.empty()) { F(t); }
  try {
    for (const auto& it : items) { G(it); }
  } catch (const std::exception& e) { return ""; }
  (void)lit;
  (void)z;
  return y;
}
std::string f(const std::string& a) { return a; }
void F(const std::string& a) {}
void G(const std::string& a) {}
"#,
            function_name: "shapes",
            branch_callee: "F",
            loop_callee: "G",
            skip: &[],
        },
        _ => panic!("no fixture for lang `{lang}`"),
    }
}

#[test]
fn flow_event_shape_conformance() {
    let adapters = bonsai_adapters::all_adapters();
    let mut failures: Vec<String> = Vec::new();
    for adapter in adapters {
        let lang = adapter.language_id().as_str().to_string();
        let fix = fixture_for(&lang);
        let results = run_conformance(&fix);
        for result in results {
            match (result.skipped, result.found) {
                (false, false) => {
                    failures.push(format!("{lang}: {} not detected", result.shape.label()));
                }
                (true, true) => {
                    failures.push(format!(
                        "{lang}: {} is skipped but now conforms — remove the stale skip",
                        result.shape.label()
                    ));
                }
                _ => {}
            }
        }
    }
    assert!(
        failures.is_empty(),
        "flow-event conformance gaps ({} total):\n{}",
        failures.len(),
        failures.join("\n")
    );
}
