use bonsai_db::AnalyzerDb;
use bonsai_lang_api::{FlowEvent, LanguageRegistry};
use bonsai_vfs::Vfs;
use std::sync::Arc;

fn db_with(source: &str) -> AnalyzerDb {
    let vfs = Arc::new(Vfs::new());
    vfs.write("C.java".to_string(), Arc::<str>::from(source));
    let registry = Arc::new(LanguageRegistry::new());
    registry.register(Arc::new(bonsai_lang_java::JavaAdapter::new()));
    let db = AnalyzerDb::new(vfs, registry);
    for file in db.vfs().all_files() {
        let _ = db.decl_index(file);
    }
    db
}

fn method_assign_targets(db: &AnalyzerDb, name: &str) -> Vec<String> {
    let global = db.global_index();
    let mut out = Vec::new();
    for file in global.all_files() {
        for decl in global.decls_in(file) {
            if decl.name != name {
                continue;
            }
            collect_assign_targets(&decl.flow_events, &mut out);
        }
    }
    out
}

fn collect_assign_targets(events: &[FlowEvent], out: &mut Vec<String>) {
    for event in events {
        match event {
            FlowEvent::Assign { target, .. } => out.push(target.clone()),
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                collect_assign_targets(then_events, out);
                collect_assign_targets(else_events, out);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                collect_assign_targets(body, out);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                collect_assign_targets(body, out);
                collect_assign_targets(catch_events, out);
                collect_assign_targets(finally_events, out);
            }
            _ => {}
        }
    }
}

#[test]
fn final_string_fields_seed_method_assignment_facts() {
    let db = db_with(
        r#"
class C {
  static final String ALG = "AES/GCM/NoPadding";
  void handle() throws Exception {
    javax.crypto.Cipher.getInstance(ALG);
  }
}
"#,
    );
    let targets = method_assign_targets(&db, "handle");
    assert!(
        targets.iter().any(|target| target == "ALG"),
        "expected final String field assignment fact to seed method flow, got {targets:?}"
    );
}

#[test]
fn final_string_field_keeps_exact_rhs_syntax_fact() {
    let db = db_with(
        r#"
class C {
  static final String ALG = "AES/GCM/NoPadding";
  void handle() throws Exception {
    javax.crypto.Cipher.getInstance(ALG);
  }
}
"#,
    );
    let file = db.vfs().all_files()[0];
    let index = db.decl_index(file).expect("Java declaration index");
    let assignment_span = index
        .defs
        .iter()
        .find(|decl| decl.name == "handle")
        .and_then(|decl| {
            decl.flow_events.iter().find_map(|event| match event {
                FlowEvent::Assign { span, target, .. } if target == "ALG" => Some(*span),
                _ => None,
            })
        })
        .expect("class constant assignment attached to method");
    let value_span = index
        .assignment_values
        .iter()
        .find_map(|fact| (fact.assignment_span == assignment_span).then_some(fact.value_span))
        .expect("exact RHS syntax fact for attached class constant");
    let snapshot = db.vfs().snapshot(file).expect("source snapshot");
    let value = &snapshot.text[value_span.start as usize..value_span.end as usize];
    assert_eq!(value, r#""AES/GCM/NoPadding""#);
}

#[test]
fn final_string_field_shadowed_by_parameter_is_not_seeded() {
    let db = db_with(
        r#"
class C {
  static final String ALG = "AES/GCM/NoPadding";
  void handle(String ALG) throws Exception {
    javax.crypto.Cipher.getInstance(ALG);
  }
}
"#,
    );
    let targets = method_assign_targets(&db, "handle");
    assert!(
        !targets.iter().any(|target| target == "ALG"),
        "parameter ALG should shadow the final String field fact, got {targets:?}"
    );
}
