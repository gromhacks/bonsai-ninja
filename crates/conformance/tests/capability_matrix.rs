//! Capability-matrix conformance test.
//!
//! Runs every bundled language adapter against a representative
//! fixture and writes the result matrix to `build/capability-matrix.{md,json}`.
//! Use as the gate for the engine-improvement-plan phases: each
//! phase moves cells from ❌ to ✅, this test prevents regressions
//! once a cell is green.

use bonsai_conformance::capability_matrix::{
    probe, write_matrix_to_build, Capability, CapabilityProbe, Cell, CellStatus,
};
use bonsai_lang_api::{LanguageAdapter, LanguageId};
use std::sync::Arc;

fn adapter_by_lang(adapter: Arc<dyn LanguageAdapter>) -> (&'static str, Arc<dyn LanguageAdapter>) {
    let id: LanguageId = adapter.language_id();
    (id.as_str(), adapter)
}

fn fixture_for(lang: &str) -> (&'static str, &'static str, &'static [Capability]) {
    match lang {
        "python" => (
            "app.py",
            "from typing import Annotated, List\nfrom fastapi import Query\n\nclass Pipeline(Base):\n    def __init__(self, conn: str):\n        self.conn = conn\n\n    def run(self, items: List[str]):\n        try:\n            for item in items:\n                if item:\n                    self.handle(item)\n        except Exception as e:\n            return e\n\n    def handle(self, x: Annotated[str, Query()] = Query(...)):\n        y = self.transform(x)\n        return y\n",
            &[Capability::ImplicitReceiverNames, Capability::ImplicitReturns],
        ),
        "javascript" => (
            "app.js",
            "const echo = (x) => x;\nclass Repo extends Base {\n  constructor(conn) { this.conn = conn; }\n  run(items) {\n    try {\n      for (const it of items) {\n        if (it) { this.handle(it); }\n      }\n    } catch (e) { return e; }\n  }\n  handle(x) { const y = this.transform(x); return y; }\n}\n",
            &[
                Capability::ParamAnnotations,
                Capability::ReceiverParamIndex,
                Capability::TypeAliases,
            ],
        ),
        "typescript" => (
            "app.ts",
            "const echo = (x: string): string => x;\nclass Repo extends Base {\n  conn: string;\n  constructor(conn: string) { this.conn = conn; }\n  run(items: string[]): void {\n    try {\n      for (const it of items) {\n        if (it) { this.handle(it); }\n      }\n    } catch (e) { return e; }\n  }\n  handle(@Body() x: string): string { const y: string = this.transform(x); return y; }\n}\n",
            &[Capability::ReceiverParamIndex],
        ),
        "java" => (
            "App.java",
            "package app;\nclass App extends Base {\n  String conn;\n  App(String conn) { this.conn = conn; }\n  void run(java.util.List<String> items) {\n    try {\n      for (String it : items) {\n        if (it != null) { this.handle(it); }\n      }\n    } catch (Exception e) { return; }\n  }\n  String handle(@Param String x) { String y = this.transform(x); return y; }\n}\n",
            &[Capability::ReceiverParamIndex, Capability::ImplicitReturns],
        ),
        "csharp" => (
            "App.cs",
            "namespace App;\nclass App : Base {\n  string conn;\n  public App(string conn) { this.conn = conn; }\n  public void Run(System.Collections.Generic.List<string> items) {\n    try {\n      foreach (var it in items) {\n        if (it != null) { Handle(it); }\n      }\n    } catch (System.Exception e) { return; }\n  }\n  public string Handle([FromBody] string x) { var y = Transform(x); return y; }\n}\n",
            &[
                Capability::ReceiverParamIndex,
                Capability::ImplicitReturns,
            ],
        ),
        "rust" => (
            "app.rs",
            "pub struct Repo { conn: String }\nimpl Repo {\n  pub fn new(conn: String) -> Self { Self { conn } }\n  pub fn run(&self, items: Vec<String>) -> Option<String> {\n    for it in items {\n      if !it.is_empty() { self.handle(&it); }\n    }\n    None\n  }\n  pub fn handle(&self, #[from_body] x: &str) -> String { let y: String = self.transform(x); y }\n  fn transform(&self, x: &str) -> String { x.to_string() }\n}\n",
            &[Capability::Bases, Capability::TryEvents],
        ),
        "go" => (
            "app.go",
            "package app\ntype Repo struct{ conn string }\nfunc New(conn string) *Repo { return &Repo{conn: conn} }\nfunc (r *Repo) SetConn(conn string) { r.conn = conn }\nfunc (r *Repo) Run(items []string) {\n  defer func() { recover() }()\n  for _, it := range items {\n    if it != \"\" { r.Handle(it) }\n  }\n}\nfunc (r *Repo) Handle(x string) string { y := r.Transform(x); return y }\nfunc (r *Repo) Transform(x string) string { return x }\n",
            &[
                Capability::Bases,
                Capability::TryEvents,
                Capability::ParamAnnotations,
                Capability::ImplicitReceiverNames,
                Capability::ImplicitReturns,
            ],
        ),
        "kotlin" => (
            "App.kt",
            "package app\nopen class Base\nclass Repo(val conn: String) : Base() {\n  fun run(items: List<String>) {\n    try {\n      for (it in items) {\n        if (it.isNotEmpty()) { handle(it) }\n      }\n    } catch (e: Exception) { return }\n  }\n  fun handle(@RequestParam x: String): String { val y: String = transform(x); return y }\n  fun transform(x: String): String = x\n}\n",
            &[Capability::ReceiverParamIndex],
        ),
        "scala" => (
            "App.scala",
            "package app\nclass Base\nclass Repo(val conn: String) extends Base {\n  def run(items: List[String]): Unit = {\n    try {\n      for (it <- items) {\n        if (it.nonEmpty) handle(it)\n      }\n    } catch { case e: Exception => () }\n  }\n  def handle(@body x: String): String = { val y: String = transform(x); y }\n  def transform(x: String): String = x\n}\n",
            &[Capability::ReceiverParamIndex],
        ),
        "swift" => (
            "App.swift",
            "class Base {}\nclass Repo: Base {\n  let conn: String\n  init(_ conn: String) { self.conn = conn }\n  func run(_ items: [String]) {\n    do {\n      for it in items {\n        if !it.isEmpty { handle(it) }\n      }\n    } catch let e {\n      _ = e\n    }\n  }\n  func handle(_ x: String, _ callback: @escaping (String) -> String) -> String { let y: String = transform(x); return callback(y) }\n  func transform(_ x: String) -> String { x }\n}\n",
            &[Capability::ReceiverParamIndex],
        ),
        "ruby" => (
            "app.rb",
            "class Base\nend\nclass Repo < Base\n  def initialize(conn)\n    @conn = conn\n  end\n\n  def run(items)\n    begin\n      for it in items\n        handle(it) if it\n      end\n    rescue => e\n      return e\n    end\n  end\n\n  def handle(x)\n    y = transform(x)\n    y\n  end\nend\n",
            &[
                Capability::ParamAnnotations,
                Capability::TypeAliases,
                Capability::ReceiverParamIndex,
            ],
        ),
        "perl" => (
            "App.pm",
            "package App;\nuse parent 'Base';\nsub new {\n  my ($class, $conn) = @_;\n  my $self = bless { conn => $conn }, $class;\n  return $self;\n}\nsub run {\n  my ($self, $items) = @_;\n  eval {\n    for my $it (@$items) {\n      if ($it) { $self->handle($it); }\n    }\n  };\n  if ($@) { return $@; }\n}\nsub handle {\n  my ($self, $x) = @_;\n  my $y = $self->transform($x);\n  return $y;\n}\n1;\n",
            &[
                Capability::ParamAnnotations,
                Capability::TypeAliases,
                Capability::ReceiverParamIndex,
                Capability::ImplicitReceiverNames,
                Capability::ImplicitReturns,
                Capability::TryEvents,
            ],
        ),
        "php" => (
            "App.php",
            "<?php\nclass Base {}\nclass Repo extends Base {\n  private $conn;\n  public function __construct($conn) { $this->conn = $conn; }\n  public function run(array $items) {\n    try {\n      foreach ($items as $it) {\n        if ($it) { $this->handle($it); }\n      }\n    } catch (\\Exception $e) { return $e; }\n  }\n  public function handle(#[Body] $x) {\n    $y = $this->transform($x);\n    return $y;\n  }\n}\n",
            &[
                Capability::TypeAliases,
                Capability::ReceiverParamIndex,
                Capability::ImplicitReturns,
            ],
        ),
        "dart" => (
            "app.dart",
            "class Base {}\nclass Repo extends Base {\n  String conn;\n  Repo(this.conn);\n  void run(List<String> items) {\n    try {\n      for (final it in items) {\n        if (it.isNotEmpty) { handle(it); }\n      }\n    } catch (e) { return; }\n  }\n  String handle(@body String x) { final y = transform(x); return y; }\n  String transform(String x) => x;\n}\n",
            &[
                Capability::ReceiverParamIndex,
                Capability::ImplicitReturns,
            ],
        ),
        "lua" => (
            "app.lua",
            "local Repo = {}\nRepo.__index = Repo\n\nfunction Repo.new(conn)\n  local self = setmetatable({}, Repo)\n  self.conn = conn\n  return self\nend\n\nfunction Repo:run(items)\n  for _, it in ipairs(items) do\n    if it then self:handle(it) end\n  end\nend\n\nfunction Repo:handle(x)\n  local y = self:transform(x)\n  return y\nend\n\nreturn Repo\n",
            &[
                Capability::Bases,
                Capability::TryEvents,
                Capability::ParamAnnotations,
                Capability::TypeAliases,
                Capability::ImplicitReceiverNames,
                Capability::CallReceiverTypes,
                Capability::ReceiverParamIndex,
                Capability::ImplicitReturns,
            ],
        ),
        "objc" => (
            "App.m",
            "#import <Foundation/Foundation.h>\n\n@interface Repo : NSObject\n@property (strong) NSString *conn;\n- (instancetype)initWithConn:(NSString *)conn;\n- (void)run:(NSArray<NSString *> *)items;\n- (NSString *)handle:(NSString *)x;\n@end\n\n@implementation Repo\n- (instancetype)initWithConn:(NSString *)conn {\n  self = [super init];\n  if (self) {\n    _conn = conn;\n  }\n  return self;\n}\n- (void)run:(NSArray<NSString *> *)items {\n  @try {\n    for (NSString *it in items) {\n      if (it.length > 0) { [self handle:it]; }\n    }\n  } @catch (NSException *e) {\n    return;\n  }\n}\n- (NSString *)handle:(NSString *)x {\n  NSString *y = [self transform:x];\n  return y;\n}\n- (NSString *)transform:(NSString *)x { return x; }\n@end\n",
            &[
                Capability::ReceiverParamIndex,
                Capability::ImplicitReturns,
            ],
        ),
        "elixir" => (
            "app.ex",
            "defmodule App.Repo do\n  defstruct [:conn]\n\n  def new(conn), do: %__MODULE__{conn: conn}\n\n  def run(items) do\n    try do\n      for it <- items do\n        if it != nil, do: handle(it)\n      end\n    rescue\n      e -> {:error, e}\n    end\n  end\n\n  def handle(x) do\n    y = transform(x)\n    y\n  end\n\n  def transform(x), do: x\nend\n",
            &[
                Capability::ParamAnnotations,
                Capability::TypeAliases,
                Capability::ReceiverParamIndex,
                Capability::ReceiverFieldWrites,
                Capability::Bases,
                Capability::ImplicitReceiverNames,
                Capability::CallReceiverTypes,
            ],
        ),
        "erlang" => (
            "app.erl",
            "-module(app).\n-export([run/2, handle/2]).\n\nrun(Conn, Items) ->\n  try\n    lists:foreach(fun(It) ->\n      case It of\n        undefined -> ok;\n        _ -> handle(Conn, It)\n      end\n    end, Items)\n  catch\n    _:E -> {error, E}\n  end.\n\nhandle(Conn, X) ->\n  Joined = Conn ++ X,\n  Y = transform(Joined, X),\n  Y.\n\ntransform(_Conn, X) -> X.\n",
            &[
                Capability::ParamAnnotations,
                Capability::TypeAliases,
                Capability::ReceiverParamIndex,
                Capability::ReceiverFieldWrites,
                Capability::Bases,
                Capability::ImplicitReceiverNames,
                Capability::CallReceiverTypes,
                Capability::LoopEvents,
            ],
        ),
        "c" => (
            "app.c",
            "#include <stdio.h>\n\ntypedef struct {\n  const char *conn;\n} Repo;\n\nRepo *repo_new(const char *conn) {\n  Repo *r = (Repo *)malloc(sizeof(Repo));\n  r->conn = conn;\n  return r;\n}\n\nint repo_run(Repo *r, const char **items, int n) {\n  for (int i = 0; i < n; i++) {\n    if (items[i]) { repo_handle(r, items[i]); }\n  }\n  return 0;\n}\n\nconst char *repo_handle(Repo *r, const char *x) {\n  const char *y = repo_transform(r, x);\n  return y;\n}\n",
            &[
                Capability::Bases,
                Capability::TryEvents,
                Capability::ParamAnnotations,
                Capability::ImplicitReceiverNames,
                Capability::ImplicitReturns,
                Capability::ReceiverFieldWrites,
                Capability::ReceiverParamIndex,
                Capability::CallReceiverTypes,
            ],
        ),
        "cpp" => (
            "app.cpp",
            "#include <string>\n#include <vector>\n#include <stdexcept>\n\nclass Base {};\nclass Repo : public Base {\npublic:\n  std::string conn;\n  Repo(std::string c) : conn(std::move(c)) {}\n  void run(const std::vector<std::string>& items) {\n    try {\n      for (const auto& it : items) {\n        if (!it.empty()) { handle(it); }\n      }\n    } catch (const std::exception& e) {\n      return;\n    }\n  }\n  std::string handle(const std::string& x) {\n    std::string y = transform(x);\n    return y;\n  }\n  std::string transform(const std::string& x) { return x; }\n};\n",
            &[
                Capability::ParamAnnotations,
                Capability::ReceiverParamIndex,
                Capability::ImplicitReturns,
            ],
        ),
        _ => panic!("no fixture for lang `{lang}`"),
    }
}

fn run_all_probes() -> Vec<Cell> {
    let adapters = bonsai_adapters::all_adapters();
    let mut cells: Vec<Cell> = Vec::new();
    for adapter in adapters {
        let (lang, adapter) = adapter_by_lang(adapter);
        let (path, source, not_applicable) = fixture_for(lang);
        let probe_spec = CapabilityProbe {
            adapter,
            fixture_path: path,
            fixture_source: source,
            not_applicable,
        };
        cells.extend(probe(&probe_spec));
    }
    cells
}

#[test]
fn capability_matrix_report() {
    let cells = run_all_probes();
    if let Err(err) = write_matrix_to_build(&cells) {
        eprintln!("warning: failed to persist capability matrix: {err}");
    }
    // Sanity: at least one Supported cell so we know the harness ran.
    let total_supported = cells
        .iter()
        .filter(|c| matches!(c.status, CellStatus::Supported))
        .count();
    assert!(total_supported > 0, "no capabilities reported as supported");
    // Sanity: 20 languages × Capability::ALL.len() cells.
    assert_eq!(
        cells.len(),
        20 * Capability::ALL.len(),
        "expected {} cells, got {}",
        20 * Capability::ALL.len(),
        cells.len()
    );
    let missing: Vec<_> = cells
        .iter()
        .filter(|cell| matches!(cell.status, CellStatus::Missing))
        .map(|cell| format!("{}:{}", cell.language, cell.capability.label()))
        .collect();
    assert!(
        missing.is_empty(),
        "all applicable compiler capabilities must be covered; mark truly unsupported syntax \
         NotApplicable with a language rationale instead of leaving silent red cells:\n{}",
        missing.join("\n")
    );
}

/// Helper for per-phase fixture suites: assert a specific capability
/// is Supported on every non-NotApplicable cell. Phases gate against
/// this once they've completed adapter rollout.
pub fn assert_capability_universal(cap: Capability) {
    let cells: Vec<Cell> = run_all_probes()
        .into_iter()
        .filter(|c| c.capability == cap)
        .collect();
    let missing: Vec<&Cell> = cells
        .iter()
        .filter(|c| matches!(c.status, CellStatus::Missing))
        .collect();
    assert!(
        missing.is_empty(),
        "capability {:?} missing in: {:?}",
        cap,
        missing.iter().map(|c| &c.language).collect::<Vec<_>>(),
    );
}
