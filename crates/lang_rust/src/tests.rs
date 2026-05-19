use super::*;
use bonsai_testkit::workspace_with;
use std::sync::Arc;

#[test]
fn extracts_top_level_function() {
    let ws = workspace_with(
        vec![Arc::new(RustAdapter::new())],
        &[("a.rs", "fn hello() {}\nfn world() { hello(); }")],
    );
    let file = ws.vfs().all_files()[0];
    let idx = ws.db().decl_index(file).unwrap();
    let names: Vec<&str> = idx.defs.iter().map(|d| d.name.as_str()).collect();
    assert!(names.contains(&"hello"));
    assert!(names.contains(&"world"));
}

#[test]
fn cfg_not_empty_for_main() {
    let ws = workspace_with(
        vec![Arc::new(RustAdapter::new())],
        &[("main.rs", "fn main() { let x = 1; }")],
    );
    let func = ws.lookup_function("main").expect("find main");
    let cfg = ws.db().cfg(func);
    assert!(!cfg.blocks.is_empty());
}

#[test]
fn format_macro_named_capture_becomes_call_arg_source_name() {
    let ws = workspace_with(
        vec![Arc::new(RustAdapter::new())],
        &[(
            "lib.rs",
            r#"fn run(cmd: &str) {
sink(format!("ping {cmd}"));
}"#,
        )],
    );
    let file = ws.vfs().all_files()[0];
    let idx = ws.db().decl_index(file).unwrap();
    let run = idx.defs.iter().find(|decl| decl.name == "run").unwrap();
    let mut found = false;
    for event in &run.flow_events {
        if let FlowEvent::Call { name, args, .. } = event {
            if name == "sink" {
                found = args
                    .first()
                    .is_some_and(|arg| arg.source_names.iter().any(|source| source == "cmd"));
            }
        }
    }
    assert!(found, "format! named capture should be adapter-emitted operand");
}

#[test]
fn module_qualified_value_call_records_receiver_for_resolution() {
    let ws = workspace_with(
        vec![Arc::new(RustAdapter::new())],
        &[(
            "src/pipeline.rs",
            r#"
use crate::storage as store;
fn run(valid: Envelope) {
    store::persist(valid);
}
"#,
        )],
    );
    let file = ws.vfs().all_files()[0];
    let idx = ws.db().decl_index(file).unwrap();
    let run = idx.defs.iter().find(|decl| decl.name == "run").unwrap();
    let call = run
        .flow_events
        .iter()
        .find_map(|event| match event {
            FlowEvent::Call { name, receiver, .. } if name == "store::persist" => Some(receiver.as_deref()),
            _ => None,
        })
        .flatten();

    assert_eq!(call, Some("store"));
}

#[test]
fn method_self_parameter_is_recorded_as_receiver_slot() {
    let ws = workspace_with(
        vec![Arc::new(RustAdapter::new())],
        &[(
            "src/storage.rs",
            r#"
struct Repository;
impl Repository {
    fn run(&self, data: &str) {
        sink(data);
    }
}
"#,
        )],
    );
    let file = ws.vfs().all_files()[0];
    let idx = ws.db().decl_index(file).unwrap();
    let run = idx.defs.iter().find(|decl| decl.name == "run").unwrap();

    assert_eq!(run.params, ["self", "data"]);
    assert_eq!(run.receiver_param_index, Some(0));
}

#[test]
fn tail_return_struct_literal_records_single_param_source() {
    let ws = workspace_with(
        vec![Arc::new(RustAdapter::new())],
        &[(
            "src/storage.rs",
            r#"
struct Envelope { cmd: String }
struct Repository { data: Envelope }
impl Repository {
    fn new(data: Envelope) -> Self {
        Self { data }
    }
}
"#,
        )],
    );
    let file = ws.vfs().all_files()[0];
    let idx = ws.db().decl_index(file).unwrap();
    let new_fn = idx.defs.iter().find(|decl| decl.name == "new").unwrap();
    let return_value = new_fn.flow_events.iter().find_map(|event| match event {
        FlowEvent::Return { value_name, .. } => value_name.as_deref(),
        _ => None,
    });

    assert_eq!(return_value, Some("data"));
}

#[test]
fn tail_return_receiver_field_records_qualified_source() {
    let ws = workspace_with(
        vec![Arc::new(RustAdapter::new())],
        &[(
            "src/storage.rs",
            r#"
struct Envelope { cmd: String }
struct Repository { data: Envelope }
impl Repository {
    fn cmd(&self) -> &str {
        &self.data.cmd
    }
}
"#,
        )],
    );
    let file = ws.vfs().all_files()[0];
    let idx = ws.db().decl_index(file).unwrap();
    let cmd = idx.defs.iter().find(|decl| decl.name == "cmd").unwrap();
    let return_value = cmd.flow_events.iter().find_map(|event| match event {
        FlowEvent::Return { value_name, .. } => value_name.as_deref(),
        _ => None,
    });

    assert_eq!(return_value, Some("self.data.cmd"));
}

#[test]
fn tuple_struct_field_receiver_records_projected_type() {
    let ws = workspace_with(
        vec![Arc::new(RustAdapter::new())],
        &[(
            "src/storage.rs",
            r#"
struct Repository;
impl Repository {
    fn run(&self) {}
}

struct AuditedRepository(Repository);
impl AuditedRepository {
    fn run(&self) {
        self.0.run();
    }
}
"#,
        )],
    );
    let file = ws.vfs().all_files()[0];
    let idx = ws.db().decl_index(file).unwrap();
    let audited_run = idx
        .defs
        .iter()
        .find(|decl| {
            decl.name == "run"
                && decl
                    .type_aliases
                    .iter()
                    .any(|alias| alias.name == "self.0" && alias.type_name == "Repository")
        })
        .unwrap();
    let receiver_types = audited_run.flow_events.iter().find_map(|event| match event {
        FlowEvent::Call {
            name,
            receiver,
            receiver_types,
            ..
        } if name == "self.0.run" && receiver.as_deref() == Some("self.0") => Some(receiver_types),
        _ => None,
    });

    assert!(receiver_types.is_some_and(|types| types.iter().any(|ty| ty == "Repository")));
}

#[test]
fn non_tuple_field_receiver_does_not_inherit_base_alias_type() {
    let ws = workspace_with(
        vec![Arc::new(RustAdapter::new())],
        &[(
            "src/storage.rs",
            r#"
struct Request;
struct Cookies;

impl Request {
    fn get_cookies(&self) -> Cookies {
        Cookies
    }
}

fn run(request: Request) {
    request.get_cookies().len();
}
"#,
        )],
    );
    let file = ws.vfs().all_files()[0];
    let idx = ws.db().decl_index(file).unwrap();
    let run = idx.defs.iter().find(|decl| decl.name == "run").unwrap();
    let receiver_types = run.flow_events.iter().find_map(|event| match event {
        FlowEvent::Call {
            receiver,
            receiver_types,
            ..
        } if receiver.as_deref() == Some("request.get_cookies()") => Some(receiver_types),
        _ => None,
    });

    assert!(receiver_types.is_some_and(Vec::is_empty));
}
