use super::*;
use bonsai_testkit::workspace_with;
use std::sync::Arc;

fn parse_import_specs(src: &str) -> Vec<ImportSpec> {
    let language = language_from_pack(PACK_NAME).expect("rust grammar");
    let mut parser = tree_sitter::Parser::new();
    parser.set_language(&language).expect("set rust grammar");
    let tree = parser.parse(src.as_bytes(), None).expect("parse rust source");
    parse_imports(&tree, src.as_bytes(), FileId::new(0))
}

#[test]
fn use_trees_are_lowered_from_cst_nodes() {
    let imports =
        parse_import_specs("use foo::{self, bar, baz as qux, nested::{A, B as C}, /* trivia */ *};\n");

    assert!(imports.iter().any(|spec| {
        spec.module == "foo" && spec.alias.as_deref() == Some("foo") && spec.original_name.is_none()
    }));
    assert!(imports.iter().any(|spec| {
        spec.module == "foo" && spec.alias.is_none() && spec.original_name.as_deref() == Some("bar")
    }));
    assert!(imports.iter().any(|spec| {
        spec.module == "foo"
            && spec.alias.as_deref() == Some("qux")
            && spec.original_name.as_deref() == Some("baz")
    }));
    assert!(imports.iter().any(|spec| {
        spec.module == "foo::nested"
            && spec.alias.as_deref() == Some("C")
            && spec.original_name.as_deref() == Some("B")
    }));
    assert!(imports
        .iter()
        .any(|spec| spec.module == "foo" && spec.is_wildcard));
}

#[test]
fn direct_rooted_use_retains_its_complete_target_once() {
    let imports = parse_import_specs("use crate::util::trace::SpawnMeta;\n");

    assert_eq!(imports.len(), 1);
    assert_eq!(imports[0].module, "crate::util::trace::SpawnMeta");
    assert_eq!(imports[0].alias, None);
    assert_eq!(imports[0].original_name, None);
}

#[test]
fn visible_use_member_lowers_as_an_exact_import_facade() {
    let ws = workspace_with(
        vec![Arc::new(RustAdapter::new())],
        &[
            (
                "Cargo.toml",
                "[package]\nname = \"adapter-fixture\"\nversion = \"0.1.0\"\n",
            ),
            ("src/runtime/task/mod.rs", "pub(crate) use self::id::Id;\n"),
        ],
    );
    let file = ws
        .vfs()
        .all_files()
        .iter()
        .copied()
        .find(|file| {
            ws.vfs()
                .path(*file)
                .is_ok_and(|path| path.extension().is_some_and(|extension| extension == "rs"))
        })
        .expect("Rust fixture file");
    let idx = ws.db().decl_index(file).unwrap();
    let alias = idx
        .defs
        .iter()
        .find(|decl| decl.kind == DeclKind::Import && decl.name == "Id")
        .expect("exported Id facade");

    assert_eq!(alias.visibility, Visibility::Crate);
    assert_eq!(alias.bases, ["self::id::Id"]);
    let expected_identity = format!("{}.Id", alias.module_path.segments.join("."));
    assert_eq!(alias.qualified_name.as_deref(), Some(expected_identity.as_str()));
}

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
fn module_qualified_call_is_a_receiverless_path_call() {
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
            FlowEvent::Call {
                name,
                receiver,
                receiver_types,
                call_kind,
                ..
            } if name == "store::persist" => Some((receiver, receiver_types, call_kind)),
            _ => None,
        })
        .expect("store::persist call");

    assert_eq!(call.0, &None);
    assert!(call.1.is_empty());
    assert_eq!(*call.2, CallKind::Function);
}

#[test]
fn generic_scoped_call_is_a_receiverless_path_call() {
    let ws = workspace_with(
        vec![Arc::new(RustAdapter::new())],
        &[(
            "src/runtime.rs",
            r#"
fn spawn<F>() {
    let _ = core::mem::size_of::<F>();
}
"#,
        )],
    );
    let file = ws.vfs().all_files()[0];
    let idx = ws.db().decl_index(file).unwrap();
    let spawn = idx.defs.iter().find(|decl| decl.name == "spawn").unwrap();
    let call = spawn
        .flow_events
        .iter()
        .find_map(|event| match event {
            FlowEvent::Call {
                name,
                receiver,
                receiver_types,
                call_kind,
                ..
            } if name == "core::mem::size_of::<F>" => Some((receiver, receiver_types, call_kind)),
            _ => None,
        })
        .expect("size_of call");

    assert_eq!(call.0, &None);
    assert!(call.1.is_empty());
    assert_eq!(*call.2, CallKind::Function);
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
mod scheduler {
    pub struct Repository;
    impl Repository {
        pub fn run(&self) {}
    }
}

struct AuditedRepository(u32, pub(crate) scheduler::Repository);
impl AuditedRepository {
    fn run(&self) {
        self.1.run();
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
                    .any(|alias| alias.name == "self.1" && alias.type_name == "scheduler.Repository")
        })
        .unwrap();
    let receiver_types = audited_run.flow_events.iter().find_map(|event| match event {
        FlowEvent::Call {
            name,
            receiver,
            receiver_types,
            ..
        } if name == "self.1.run" && receiver.as_deref() == Some("self.1") => Some(receiver_types),
        _ => None,
    });

    assert!(receiver_types.is_some_and(|types| types.iter().any(|ty| ty == "scheduler.Repository")));
}

#[test]
fn named_struct_field_receiver_records_declared_type() {
    let ws = workspace_with(
        vec![Arc::new(RustAdapter::new())],
        &[(
            "src/runtime.rs",
            r#"
mod scheduler {
    struct Handle;
    impl Handle {
        fn spawn_named(&self) {}
    }
}

struct Runtime {
    handle: scheduler::Handle,
}
impl Runtime {
    fn spawn(&self) {
        self.handle.spawn_named();
    }
}
"#,
        )],
    );
    let file = ws.vfs().all_files()[0];
    let idx = ws.db().decl_index(file).unwrap();
    let spawn = idx
        .defs
        .iter()
        .find(|decl| {
            decl.name == "spawn"
                && decl
                    .type_aliases
                    .iter()
                    .any(|alias| alias.name == "self.handle" && alias.type_name == "scheduler.Handle")
        })
        .expect("Runtime::spawn should inherit the named field's declared type");
    let receiver_types = spawn.flow_events.iter().find_map(|event| match event {
        FlowEvent::Call {
            name,
            receiver,
            receiver_types,
            ..
        } if name == "self.handle.spawn_named" && receiver.as_deref() == Some("self.handle") => {
            Some(receiver_types)
        }
        _ => None,
    });

    let receiver_types = receiver_types.expect("self.handle.spawn_named call should be lowered");
    assert_eq!(
        receiver_types.as_slice(),
        ["scheduler.Handle"],
        "the qualified field type must not be weakened to a same-named local type"
    );
}

#[test]
fn item_macro_wrapped_impl_is_lowered_at_original_offsets() {
    let source = r#"
macro_rules! configured_items {
    ($($item:item)*) => { $($item)* };
}

enum Scheduler {
    Current,
}

configured_items! {
    impl Scheduler {
        fn dispatch(&self) {
            self.run_queue();
        }

        fn run_queue(&self) {}
    }
}
"#;
    let ws = workspace_with(
        vec![Arc::new(RustAdapter::new())],
        &[("src/scheduler.rs", source)],
    );
    let file = ws.vfs().all_files()[0];
    let idx = ws.db().decl_index(file).unwrap();
    let scheduler = idx
        .defs
        .iter()
        .find(|decl| decl.name == "Scheduler" && decl.kind == DeclKind::Enum)
        .expect("macro fixture enum");
    let dispatch = idx
        .defs
        .iter()
        .find(|decl| decl.name == "dispatch")
        .expect("item-macro impl method should be compiled");
    let run_queue = idx
        .defs
        .iter()
        .find(|decl| decl.name == "run_queue")
        .expect("every item in the macro body should be compiled");

    assert_eq!(dispatch.parent, Some(scheduler.symbol));
    assert_eq!(run_queue.parent, Some(scheduler.symbol));
    assert_eq!(
        &source.as_bytes()[dispatch.name_span.start as usize..dispatch.name_span.end as usize],
        b"dispatch",
        "the compiler view must preserve source byte offsets"
    );
    assert!(dispatch.flow_events.iter().any(|event| matches!(
        event,
        FlowEvent::Call { name, .. } if name == "self.run_queue"
    )));
}

#[test]
fn self_tuple_struct_expression_is_a_constructor_call() {
    let ws = workspace_with(
        vec![Arc::new(RustAdapter::new())],
        &[(
            "src/storage.rs",
            r#"
struct Payload { cmd: String }
struct Inner { data: Payload }
impl Inner {
    fn assemble(data: Payload) -> Self {
        Self { data }
    }
}

struct Wrapper(Inner);
impl Wrapper {
    fn from_payload(data: Payload) -> Self {
        Self(Inner::assemble(data))
    }
}
"#,
        )],
    );
    let file = ws.vfs().all_files()[0];
    let idx = ws.db().decl_index(file).unwrap();
    let factory = idx.defs.iter().find(|decl| decl.name == "from_payload").unwrap();
    let self_call = factory.flow_events.iter().find_map(|event| match event {
        FlowEvent::Call { name, call_kind, .. } if name == "Self" => Some(*call_kind),
        _ => None,
    });
    let declared_factory_call = factory.flow_events.iter().find_map(|event| match event {
        FlowEvent::Call { name, call_kind, .. } if name == "Inner::assemble" => Some(*call_kind),
        _ => None,
    });

    assert_eq!(self_call, Some(CallKind::Constructor));
    assert_eq!(declared_factory_call, Some(CallKind::Constructor));
    assert!(
        factory
            .receiver_field_writes
            .iter()
            .any(|write| { write.target == "self.0.data" && write.source_param_indices == [0] }),
        "newtype factory should project its input through the tuple field using declaration facts: {:?}",
        factory.receiver_field_writes
    );
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
