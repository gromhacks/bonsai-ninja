//! Multiple exception handlers are alternatives, never a sequential block.
//!
//! The compiler IR must preserve that distinction before CFG/IDG lowering.
//! Otherwise a value written in one typed catch can flow into a sink in an
//! incompatible sibling catch. Languages without multiple catch-arm syntax
//! are explicitly listed with a rationale so coverage cannot disappear via a
//! silent skip.

use bonsai_lang_api::{Decl, FlowEvent, LanguageAdapter};
use bonsai_workspace::Workspace;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

struct Fixture {
    path: &'static str,
    function: &'static str,
    source: &'static str,
}

enum Support {
    Applicable(Fixture),
    NotApplicable(&'static str),
}

struct Case {
    language: &'static str,
    support: Support,
}

const CASES: &[Case] = &[
    Case { language: "c", support: Support::NotApplicable("C has no exception/catch syntax") },
    Case { language: "cpp", support: Support::Applicable(Fixture { path: "catch.cpp", function: "dispatch", source: "void dispatch() { try { risky(); } catch (const FirstError& e) { catch_first(); } catch (const SecondError& e) { catch_second(); } }\n" }) },
    Case { language: "csharp", support: Support::Applicable(Fixture { path: "Catch.cs", function: "Dispatch", source: "class Catch { void Dispatch() { try { Risky(); } catch (FirstException e) { CatchFirst(); } catch (SecondException e) { CatchSecond(); } } }\n" }) },
    Case { language: "dart", support: Support::Applicable(Fixture { path: "catch.dart", function: "dispatch", source: "void dispatch() { try { risky(); } on FormatException catch (e) { catch_first(); } on Exception catch (e) { catch_second(); } }\n" }) },
    Case { language: "elixir", support: Support::Applicable(Fixture { path: "catch.ex", function: "dispatch", source: "defmodule Catch do\n  def dispatch do\n    try do\n      risky()\n    rescue\n      e in ArgumentError -> catch_first()\n      e in RuntimeError -> catch_second()\n    end\n  end\nend\n" }) },
    Case { language: "erlang", support: Support::Applicable(Fixture { path: "catch.erl", function: "dispatch", source: "-module(catch_flow).\n-export([dispatch/0]).\ndispatch() -> try risky() catch throw:first -> catch_first(); throw:second -> catch_second() end.\n" }) },
    Case { language: "go", support: Support::NotApplicable("Go has panic/recover but no catch-arm syntax") },
    Case { language: "java", support: Support::Applicable(Fixture { path: "Catch.java", function: "dispatch", source: "class Catch { void dispatch() { try { risky(); } catch (FirstException e) { catch_first(); } catch (SecondException e) { catch_second(); } } }\n" }) },
    Case { language: "javascript", support: Support::NotApplicable("JavaScript permits one catch clause per try") },
    Case { language: "kotlin", support: Support::Applicable(Fixture { path: "catch.kt", function: "dispatch", source: "fun dispatch() { try { risky() } catch (e: FirstException) { catch_first() } catch (e: SecondException) { catch_second() } }\n" }) },
    Case { language: "lua", support: Support::NotApplicable("Lua has protected calls but no catch-arm syntax") },
    Case { language: "objc", support: Support::Applicable(Fixture { path: "catch.m", function: "dispatch", source: "void dispatch() { @try { risky(); } @catch (FirstException *e) { catch_first(); } @catch (SecondException *e) { catch_second(); } }\n" }) },
    Case { language: "perl", support: Support::NotApplicable("core Perl eval has no typed catch-arm syntax") },
    Case { language: "php", support: Support::Applicable(Fixture { path: "catch.php", function: "dispatch", source: "<?php\nfunction dispatch() { try { risky(); } catch (FirstException $e) { catch_first(); } catch (SecondException $e) { catch_second(); } }\n" }) },
    Case { language: "python", support: Support::Applicable(Fixture { path: "catch.py", function: "dispatch", source: "def dispatch():\n    try:\n        risky()\n    except FirstError as e:\n        catch_first()\n    except SecondError as e:\n        catch_second()\n" }) },
    Case { language: "ruby", support: Support::Applicable(Fixture { path: "catch.rb", function: "dispatch", source: "def dispatch\n  begin\n    risky()\n  rescue FirstError => e\n    catch_first()\n  rescue SecondError => e\n    catch_second()\n  end\nend\n" }) },
    Case { language: "rust", support: Support::NotApplicable("Rust models recoverable failure with Result/match, not catch clauses") },
    Case { language: "scala", support: Support::Applicable(Fixture { path: "Catch.scala", function: "dispatch", source: "object Catch { def dispatch(): Unit = try risky() catch { case e: FirstException => catch_first(); case e: SecondException => catch_second() } }\n" }) },
    Case { language: "swift", support: Support::Applicable(Fixture { path: "catch.swift", function: "dispatch", source: "func dispatch() { do { try risky() } catch is FirstError { catch_first() } catch is SecondError { catch_second() } }\n" }) },
    Case { language: "typescript", support: Support::NotApplicable("TypeScript permits one catch clause per try") },
];

fn adapter_for(language: &str) -> Arc<dyn LanguageAdapter> {
    bonsai_adapters::all_adapters()
        .into_iter()
        .find(|adapter| adapter.language_id().as_str() == language)
        .unwrap_or_else(|| panic!("missing bundled adapter for {language}"))
}

fn find_decl(workspace: &Workspace, name: &str) -> Decl {
    let global = workspace.db().global_index();
    let found = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.name == name)
        .cloned();
    found.unwrap_or_else(|| panic!("missing `{name}` declaration"))
}

fn marker(name: &str) -> Option<&'static str> {
    let member = name
        .rsplit(['.', ':', '\\'])
        .find(|part| !part.is_empty())
        .unwrap_or(name)
        .to_ascii_lowercase();
    match member.as_str() {
        "catch_first" | "catchfirst" => Some("catch_first"),
        "catch_second" | "catchsecond" => Some("catch_second"),
        _ => None,
    }
}

fn paths(events: &[FlowEvent], initial: &[BTreeSet<&'static str>]) -> Vec<BTreeSet<&'static str>> {
    let mut out = initial.to_vec();
    for event in events {
        match event {
            FlowEvent::Call { name, .. } => {
                if let Some(marker) = marker(name) {
                    for path in &mut out {
                        path.insert(marker);
                    }
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                out = paths(then_events, &out)
                    .into_iter()
                    .chain(paths(else_events, &out))
                    .collect();
            }
            FlowEvent::Loop {
                condition_events,
                body,
                update_events,
                ..
            } => {
                out = paths(condition_events, &out);
                out = paths(body, &out);
                out = paths(update_events, &out);
            }
            FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                out = paths(body, &out);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                out = paths(body, &out)
                    .into_iter()
                    .chain(paths(catch_events, &out))
                    .collect();
                out = paths(finally_events, &out);
            }
            _ => {}
        }
    }
    out
}

fn find_catch_paths(
    events: &[FlowEvent],
) -> Option<(Vec<BTreeSet<&'static str>>, &[bonsai_lang_api::CatchArmFact])> {
    for event in events {
        match event {
            FlowEvent::Try {
                catch_events,
                catch_arms,
                ..
            } => {
                return Some((paths(catch_events, &[BTreeSet::new()]), catch_arms));
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                if let Some(found) = find_catch_paths(then_events).or_else(|| find_catch_paths(else_events)) {
                    return Some(found);
                }
            }
            FlowEvent::Loop {
                condition_events,
                body,
                update_events,
                ..
            } => {
                if let Some(found) = find_catch_paths(condition_events)
                    .or_else(|| find_catch_paths(body))
                    .or_else(|| find_catch_paths(update_events))
                {
                    return Some(found);
                }
            }
            FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                if let Some(found) = find_catch_paths(body) {
                    return Some(found);
                }
            }
            _ => {}
        }
    }
    None
}

#[test]
fn every_applicable_language_preserves_multiple_catch_arms_as_alternatives() {
    let bundled: BTreeSet<String> = bonsai_adapters::all_adapters()
        .into_iter()
        .map(|adapter| adapter.language_id().as_str().to_string())
        .collect();
    let classified: BTreeSet<String> = CASES.iter().map(|case| case.language.to_string()).collect();
    assert_eq!(
        classified, bundled,
        "every adapter needs an explicit catch-arm classification"
    );
    assert_eq!(classified.len(), CASES.len(), "duplicate catch classification");
    for case in CASES {
        if let Support::NotApplicable(reason) = case.support {
            assert!(
                !reason.trim().is_empty(),
                "{} has an unexplained N/A",
                case.language
            );
        }
    }

    let mut failures = BTreeMap::new();
    for case in CASES {
        let Support::Applicable(fixture) = &case.support else {
            continue;
        };
        let workspace = bonsai_testkit::workspace_with(
            vec![adapter_for(case.language)],
            &[(fixture.path, fixture.source)],
        );
        let diagnostics = workspace.diagnostics();
        if !diagnostics.is_empty() {
            failures.insert(
                case.language,
                format!("valid fixture diagnostics: {diagnostics:#?}"),
            );
            continue;
        }
        let decl = find_decl(&workspace, fixture.function);
        let Some((catch_paths, catch_arms)) = find_catch_paths(&decl.flow_events) else {
            failures.insert(case.language, format!("no Try event: {:#?}", decl.flow_events));
            continue;
        };
        let observed: BTreeSet<&str> = catch_paths.iter().flat_map(|path| path.iter().copied()).collect();
        let expected = BTreeSet::from(["catch_first", "catch_second"]);
        if catch_arms.len() != 2 {
            failures.insert(
                case.language,
                format!(
                    "expected two ordered arm-local compiler facts, found {}: {:#?}",
                    catch_arms.len(),
                    decl.flow_events
                ),
            );
        } else if observed != expected {
            failures.insert(
                case.language,
                format!(
                    "missing catch marker: {observed:?}; events={:#?}",
                    decl.flow_events
                ),
            );
        } else if let Some(impossible) = catch_paths.iter().find(|path| path.len() > 1) {
            failures.insert(
                case.language,
                format!(
                    "sequentialized sibling catches {impossible:?}; events={:#?}",
                    decl.flow_events
                ),
            );
        }
    }
    assert!(
        failures.is_empty(),
        "multiple-catch compiler regressions:\n{failures:#?}"
    );
}
