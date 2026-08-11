use bonsai_db::AnalyzerDb;
use bonsai_lang_api::{AssignValueKind, FlowEvent, LanguageRegistry};
use bonsai_vfs::Vfs;
use std::sync::Arc;

fn db_with(source: &str) -> AnalyzerDb {
    let vfs = Arc::new(Vfs::new());
    vfs.write("app.php".to_string(), Arc::<str>::from(source));
    let registry = Arc::new(LanguageRegistry::new());
    registry.register(Arc::new(bonsai_lang_php::PhpAdapter::new()));
    let db = AnalyzerDb::new(vfs, registry);
    for file in db.vfs().all_files() {
        let _ = db.decl_index(file);
    }
    db
}

fn collect_calls(events: &[FlowEvent], out: &mut Vec<(String, Vec<String>)>) {
    for event in events {
        match event {
            FlowEvent::Call {
                name, receiver_types, ..
            } => out.push((name.clone(), receiver_types.clone())),
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                collect_calls(then_events, out);
                collect_calls(else_events, out);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                collect_calls(body, out);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                collect_calls(body, out);
                collect_calls(catch_events, out);
                collect_calls(finally_events, out);
            }
            _ => {}
        }
    }
}

#[test]
fn sigiled_receiver_uses_parameter_type() {
    let db = db_with(
        r#"
<?php
function save(PDOStatement $stmt, $id) {
  $stmt->execute([$id]);
}
"#,
    );
    let global = db.global_index();
    let mut calls = Vec::new();
    for file in global.all_files() {
        for decl in global.decls_in(file) {
            if decl.name == "save" {
                collect_calls(&decl.flow_events, &mut calls);
            }
        }
    }
    assert!(
        calls.iter().any(|(name, receiver_types)| {
            name.ends_with("execute") && receiver_types.iter().any(|ty| ty == "PDOStatement")
        }),
        "PHP sigiled receiver should inherit parameter type, got {calls:?}"
    );
}

#[test]
fn implicit_this_receiver_uses_enclosing_class_and_bases() {
    let db = db_with(
        r#"
<?php
class BaseRepository {
  public function cmd(): string { return "clean"; }
}
class Repository extends BaseRepository {
  public function run(): string { return $this->cmd(); }
}
"#,
    );
    let global = db.global_index();
    let run = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.name == "run")
        .expect("run method should be indexed");
    let mut calls = Vec::new();
    collect_calls(&run.flow_events, &mut calls);

    assert!(
        calls.iter().any(|(name, receiver_types)| {
            name.ends_with("cmd")
                && receiver_types.iter().any(|ty| ty == "Repository")
                && receiver_types.iter().any(|ty| ty == "BaseRepository")
        }),
        "PHP's Tree-sitter adapter must type `$this` from the enclosing declaration hierarchy, got {calls:?}"
    );
}

#[test]
fn parenthesized_inline_constructor_types_member_receiver() {
    let db = db_with(
        r#"
<?php
class Util { public function helper($value) {} }
function entry($args) { (new Util())->helper($args); }
"#,
    );
    let global = db.global_index();
    let entry = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.name == "entry")
        .expect("entry function should be indexed");
    let mut calls = Vec::new();
    collect_calls(&entry.flow_events, &mut calls);

    assert!(
        calls.iter().any(|(name, receiver_types)| {
            name.ends_with("helper") && receiver_types.iter().any(|ty| ty == "Util")
        }),
        "PHP's adapter-extracted constructor target must type an inline member receiver, got {calls:?}"
    );
}

#[test]
fn class_declaration_records_extends_base() {
    let db = db_with(
        r#"
<?php
namespace App;
class Base {}
namespace;
use App\Base;
class Child extends Base {}
"#,
    );
    let global = db.global_index();
    let child = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.name == "Child")
        .expect("Child class should be indexed");

    assert_eq!(child.bases, vec!["Base"]);
}

#[test]
fn simple_variable_assignment_uses_exact_source_name() {
    let db = db_with("<?php\nfunction handle($x) { $y = $x; sink($y); }\nfunction sink($s) {}\n");
    let global = db.global_index();
    let handle = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.name == "handle")
        .expect("handle function should be indexed");

    assert!(
        handle.flow_events.iter().any(|event| matches!(
            event,
            FlowEvent::Assign {
                target,
                source_name: Some(source),
                ..
            } if target == "$y" && source == "$x"
        )),
        "PHP simple variable rename should use exact source_name, got {:#?}",
        handle.flow_events
    );
}

#[test]
fn member_access_assignment_stays_compound() {
    let db = db_with("<?php\nfunction handle($obj) { $y = $obj->token; sink($y); }\nfunction sink($s) {}\n");
    let global = db.global_index();
    let handle = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.name == "handle")
        .expect("handle function should be indexed");

    assert!(
        handle.flow_events.iter().any(|event| matches!(
            event,
            FlowEvent::Assign {
                target,
                source_name: None,
                source_names,
                ..
            } if target == "$y" && source_names.iter().any(|source| source == "$obj.token")
        )),
        "PHP member access should stay on qualified compound source_names, got {:#?}",
        handle.flow_events
    );
}

#[test]
fn member_access_inside_compound_expression_keeps_sigiled_projection() {
    let db = db_with(
        "<?php\nfunction handle($obj) { $size = $obj->capacity * 2; sink($size); }\nfunction sink($s) {}\n",
    );
    let global = db.global_index();
    let handle = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.name == "handle")
        .expect("handle function should be indexed");

    assert!(
        handle.flow_events.iter().any(|event| matches!(
            event,
            FlowEvent::Assign {
                target,
                source_names,
                ..
            } if target == "$size" && source_names.iter().any(|source| source == "$obj.capacity")
        )),
        "PHP compound member read should retain its exact sigiled projection, got {:#?}",
        handle.flow_events
    );
}

#[test]
fn keyed_array_destructure_reads_the_selected_rhs_field() {
    let db = db_with(
        "<?php\nfunction handle($envelope) { ['cmd' => $cmd, 'user' => $user] = $envelope; sink($cmd); }\nfunction sink($s) {}\n",
    );
    let global = db.global_index();
    let handle = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.name == "handle")
        .expect("handle function should be indexed");

    for (target, expected_source) in [("cmd", "$envelope.cmd"), ("user", "$envelope.user")] {
        assert!(
            handle.flow_events.iter().any(|event| matches!(
                event,
                FlowEvent::Assign {
                    target: actual_target,
                    source_name: Some(source),
                    source_names,
                    ..
                } if actual_target == target
                    && source == expected_source
                    && source_names == &vec![expected_source.to_string()]
            )),
            "PHP keyed destructure should retain {target} <- {expected_source}, got {:#?}",
            handle.flow_events
        );
    }
}

#[test]
fn quoted_runtime_callable_is_lowered_to_typed_callable_reference() {
    let db = db_with("<?php\nfunction helper($x) {}\nfunction entry($arg) { $cb = 'helper'; $cb($arg); }\n");
    let global = db.global_index();
    let entry = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.name == "entry")
        .expect("entry function should be indexed");

    assert!(entry.flow_events.iter().any(|event| matches!(
        event,
        FlowEvent::Assign {
            target,
            source_name: Some(source),
            value_kind: Some(AssignValueKind::CallableReference),
            ..
        } if target == "$cb" && source == "helper"
    )));
}

#[test]
fn ordinary_quoted_string_remains_a_literal_overwrite() {
    let db = db_with("<?php\nfunction entry() { $value = 'helper'; return $value; }\n");
    let global = db.global_index();
    let entry = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.name == "entry")
        .expect("entry function should be indexed");

    assert!(entry.flow_events.iter().any(|event| matches!(
        event,
        FlowEvent::Assign {
            target,
            source_name: None,
            source_call: None,
            source_names,
            value_kind: Some(AssignValueKind::Literal),
            ..
        } if target == "$value" && source_names.is_empty()
    )));
}
