//! Exact multi-arm control-flow conformance for every bundled language.
//!
//! Presence-only tests are insufficient here: a flattened switch still
//! contains every call while inventing impossible paths from one arm into
//! another. These fixtures therefore require each marker call to exist and
//! prove that no compiler path can visit two mutually exclusive arms. The
//! path interpreter deliberately mirrors the IDG's treatment of FlowEvent
//! (Break/Continue carry no value transfer of their own), so a flattened arm
//! list cannot hide behind a terminator token that the dataflow layer ignores.

use bonsai_lang_api::{Decl, FlowEvent, LanguageAdapter};
use bonsai_workspace::Workspace;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

const MARKERS: [&str; 3] = ["arm_zero", "arm_one", "arm_default"];

struct Fixture {
    language: &'static str,
    path: &'static str,
    function: &'static str,
    source: &'static str,
}

const FIXTURES: &[Fixture] = &[
    Fixture {
        language: "c",
        path: "case.c",
        function: "dispatch",
        source: "void dispatch(int x) { switch (x) { case 0: arm_zero(); break; case 1: arm_one(); break; default: arm_default(); } }\n",
    },
    Fixture {
        language: "cpp",
        path: "case.cpp",
        function: "dispatch",
        source: "void dispatch(int x) { switch (x) { case 0: arm_zero(); break; case 1: arm_one(); break; default: arm_default(); } }\n",
    },
    Fixture {
        language: "csharp",
        path: "Case.cs",
        function: "Dispatch",
        source: "class Case { static void Dispatch(int x) { switch (x) { case 0: ArmZero(); break; case 1: ArmOne(); break; default: ArmDefault(); break; } } static void ArmZero() {} static void ArmOne() {} static void ArmDefault() {} }\n",
    },
    Fixture {
        language: "dart",
        path: "case.dart",
        function: "dispatch",
        source: "void dispatch(int x) { switch (x) { case 0: arm_zero(); break; case 1: arm_one(); break; default: arm_default(); } }\n",
    },
    Fixture {
        language: "elixir",
        path: "case.ex",
        function: "dispatch",
        source: "defmodule Case do\n  def dispatch(x) do\n    case x do\n      0 -> arm_zero()\n      1 -> arm_one()\n      _ -> arm_default()\n    end\n  end\nend\n",
    },
    Fixture {
        language: "erlang",
        path: "case.erl",
        function: "dispatch",
        source: "-module(case_flow).\n-export([dispatch/1]).\ndispatch(X) -> case X of 0 -> arm_zero(); 1 -> arm_one(); _ -> arm_default() end.\n",
    },
    Fixture {
        language: "go",
        path: "case.go",
        function: "dispatch",
        source: "package caseflow\nfunc dispatch(x int) { switch x { case 0: arm_zero(); case 1: arm_one(); default: arm_default() } }\n",
    },
    Fixture {
        language: "java",
        path: "Case.java",
        function: "dispatch",
        source: "class Case { static void dispatch(int x) { switch (x) { case 0: arm_zero(); break; case 1: arm_one(); break; default: arm_default(); } } }\n",
    },
    Fixture {
        language: "javascript",
        path: "case.js",
        function: "dispatch",
        source: "function dispatch(x) { switch (x) { case 0: arm_zero(); break; case 1: arm_one(); break; default: arm_default(); } }\n",
    },
    Fixture {
        language: "kotlin",
        path: "case.kt",
        function: "dispatch",
        source: "fun dispatch(x: Int) { when (x) { 0 -> arm_zero(); 1 -> arm_one(); else -> arm_default() } }\n",
    },
    Fixture {
        language: "lua",
        path: "case.lua",
        function: "dispatch",
        source: "local function dispatch(x)\n  if x == 0 then arm_zero() elseif x == 1 then arm_one() else arm_default() end\nend\n",
    },
    Fixture {
        language: "objc",
        path: "case.m",
        function: "dispatch",
        source: "void dispatch(int x) { switch (x) { case 0: arm_zero(); break; case 1: arm_one(); break; default: arm_default(); } }\n",
    },
    Fixture {
        language: "perl",
        path: "case.pl",
        function: "dispatch",
        source: "sub dispatch { my ($x) = @_; if ($x == 0) { arm_zero(); } elsif ($x == 1) { arm_one(); } else { arm_default(); } }\n",
    },
    Fixture {
        language: "php",
        path: "case.php",
        function: "dispatch",
        source: "<?php\nfunction dispatch($x) { switch ($x) { case 0: arm_zero(); break; case 1: arm_one(); break; default: arm_default(); } }\n",
    },
    Fixture {
        language: "python",
        path: "case.py",
        function: "dispatch",
        source: "def dispatch(x):\n    match x:\n        case 0:\n            arm_zero()\n        case 1:\n            arm_one()\n        case _:\n            arm_default()\n",
    },
    Fixture {
        language: "ruby",
        path: "case.rb",
        function: "dispatch",
        source: "def dispatch(x)\n  case x\n  when 0 then arm_zero()\n  when 1 then arm_one()\n  else arm_default()\n  end\nend\n",
    },
    Fixture {
        language: "rust",
        path: "case.rs",
        function: "dispatch",
        source: "fn dispatch(x: i32) { match x { 0 => arm_zero(), 1 => arm_one(), _ => arm_default() }; }\n",
    },
    Fixture {
        language: "scala",
        path: "Case.scala",
        function: "dispatch",
        source: "object Case { def dispatch(x: Int): Unit = x match { case 0 => arm_zero(); case 1 => arm_one(); case _ => arm_default() } }\n",
    },
    Fixture {
        language: "swift",
        path: "case.swift",
        function: "dispatch",
        source: "func dispatch(x: Int) { switch x { case 0: arm_zero(); case 1: arm_one(); default: arm_default() } }\n",
    },
    Fixture {
        language: "typescript",
        path: "case.ts",
        function: "dispatch",
        source: "function dispatch(x: number): void { switch (x) { case 0: arm_zero(); break; case 1: arm_one(); break; default: arm_default(); } }\n",
    },
];

fn adapter_for(language: &str) -> Arc<dyn LanguageAdapter> {
    bonsai_adapters::all_adapters()
        .into_iter()
        .find(|adapter| adapter.language_id().as_str() == language)
        .unwrap_or_else(|| panic!("missing bundled adapter for {language}"))
}

fn find_decl(workspace: &Workspace, name: &str) -> Decl {
    let global = workspace.db().global_index();
    let declaration = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.name == name)
        .cloned();
    declaration.unwrap_or_else(|| panic!("missing `{name}` declaration"))
}

fn marker(name: &str) -> Option<&'static str> {
    let member = name
        .rsplit(['.', ':', '\\'])
        .find(|part| !part.is_empty())
        .unwrap_or(name)
        .to_ascii_lowercase();
    match member.as_str() {
        "arm_zero" | "armzero" => Some("arm_zero"),
        "arm_one" | "armone" => Some("arm_one"),
        "arm_default" | "armdefault" => Some("arm_default"),
        _ => None,
    }
}

fn expand_paths(events: &[FlowEvent], initial: &[BTreeSet<&'static str>]) -> Vec<BTreeSet<&'static str>> {
    let mut paths = initial.to_vec();
    for event in events {
        match event {
            FlowEvent::Call { name, .. } => {
                if let Some(marker) = marker(name) {
                    for path in &mut paths {
                        path.insert(marker);
                    }
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                let then_paths = expand_paths(then_events, &paths);
                let else_paths = expand_paths(else_events, &paths);
                paths = then_paths.into_iter().chain(else_paths).collect();
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                paths.extend(expand_paths(body, &paths));
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                let try_paths = expand_paths(body, &paths);
                let catch_paths = expand_paths(catch_events, &paths);
                paths = try_paths.into_iter().chain(catch_paths).collect();
                paths = expand_paths(finally_events, &paths);
            }
            _ => {}
        }
    }
    paths
}

#[test]
fn every_language_preserves_mutually_exclusive_multi_arm_paths() {
    let bundled: BTreeSet<String> = bonsai_adapters::all_adapters()
        .into_iter()
        .map(|adapter| adapter.language_id().as_str().to_string())
        .collect();
    let covered: BTreeSet<String> = FIXTURES
        .iter()
        .map(|fixture| fixture.language.to_string())
        .collect();
    assert_eq!(
        covered, bundled,
        "fixture table must cover every bundled adapter exactly once"
    );
    assert_eq!(covered.len(), FIXTURES.len(), "duplicate language fixture");

    let mut failures = BTreeMap::new();
    for fixture in FIXTURES {
        let workspace = bonsai_testkit::workspace_with(
            vec![adapter_for(fixture.language)],
            &[(fixture.path, fixture.source)],
        );
        let diagnostics = workspace.diagnostics();
        if !diagnostics.is_empty() {
            failures.insert(
                fixture.language,
                format!("valid fixture emitted diagnostics: {diagnostics:#?}"),
            );
            continue;
        }
        let decl = find_decl(&workspace, fixture.function);
        let paths = expand_paths(&decl.flow_events, &[BTreeSet::new()]);
        let observed: BTreeSet<&str> = paths.iter().flat_map(|path| path.iter().copied()).collect();
        if observed != BTreeSet::from(MARKERS) {
            failures.insert(
                fixture.language,
                format!(
                    "missing arm marker(s): observed={observed:?}; events={:#?}",
                    decl.flow_events
                ),
            );
            continue;
        }
        if let Some(impossible) = paths.iter().find(|path| path.len() > 1) {
            failures.insert(
                fixture.language,
                format!(
                    "compiler invented a path through mutually exclusive arms {impossible:?}; events={:#?}",
                    decl.flow_events
                ),
            );
        }
    }

    assert!(
        failures.is_empty(),
        "multi-arm compiler conformance failures:\n{failures:#?}"
    );
}
