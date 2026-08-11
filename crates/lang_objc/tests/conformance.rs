use bonsai_conformance::run_language_suite;
use std::sync::Arc;

#[test]
fn conformance_traced() {
    let adapter: Arc<dyn bonsai_lang_api::LanguageAdapter> = Arc::new(bonsai_lang_objc::ObjCAdapter::new());
    run_language_suite!(
        adapter,
        trace_from = "main",
        [(
            "main.m",
            "void helper(void) {}\nint main(void) { helper(); return 0; }\n"
        )]
    );
}

#[test]
fn objc_call_arguments_use_ast_value_kinds_not_identifier_spelling() {
    use bonsai_diagnostics::DiagnosticSink;
    use bonsai_lang_api::{AdapterContext, AssignValueKind, LanguageAdapter};
    use bonsai_vfs::Vfs;
    use parking_lot::RwLock;

    let adapter = bonsai_lang_objc::ObjCAdapter::new();
    let vfs = Vfs::new();
    let file = vfs.write(
        std::path::Path::new("values.m"),
        "void emit(NSString*, NSString*, int);\n\
         void run(NSString *USER_VALUE) { emit(@\"literal\", USER_VALUE, 42); }\n",
    );
    let diagnostics = RwLock::new(DiagnosticSink::default());
    let index = adapter.extract_declarations(
        file,
        &AdapterContext {
            vfs: &vfs,
            diagnostics: &diagnostics,
            tree_provider: None,
            workspace_root: None,
        },
    );
    let kind = |argument_index| {
        index
            .call_argument_values
            .iter()
            .find(|fact| fact.argument_index == argument_index)
            .and_then(|fact| fact.value_kind)
    };

    assert_eq!(kind(0), Some(AssignValueKind::Literal));
    assert_eq!(kind(1), None, "ALL_CAPS is still a dynamic parameter");
    assert_eq!(kind(2), Some(AssignValueKind::Literal));
    let run = index
        .defs
        .iter()
        .find(|decl| decl.name == "run")
        .expect("run declaration");
    let emitted_args = run
        .flow_events
        .iter()
        .find_map(|event| match event {
            bonsai_lang_api::FlowEvent::Call { name, args, .. } if name == "emit" => Some(args),
            _ => None,
        })
        .expect("emit call");
    assert_eq!(
        emitted_args.len(),
        3,
        "C-style argument containers and Objective-C direct message arguments must not both lower"
    );
}

#[test]
fn property_reads_after_zero_argument_messages_keep_the_exact_place() {
    use bonsai_diagnostics::DiagnosticSink;
    use bonsai_lang_api::{AdapterContext, LanguageAdapter, RefKind};
    use bonsai_vfs::Vfs;
    use parking_lot::RwLock;

    let adapter = bonsai_lang_objc::ObjCAdapter::new();
    let vfs = Vfs::new();
    let file = vfs.write(
        std::path::Path::new("process.m"),
        "void inspect_process(void) { id a = [NSProcessInfo processInfo].arguments; id e = [NSProcessInfo processInfo].environment; }\n",
    );
    let diagnostics = RwLock::new(DiagnosticSink::default());
    let index = adapter.extract_declarations(
        file,
        &AdapterContext {
            vfs: &vfs,
            diagnostics: &diagnostics,
            tree_provider: None,
            workspace_root: None,
        },
    );
    let reads = index
        .refs
        .iter()
        .filter(|reference| reference.kind == RefKind::Read)
        .map(|reference| reference.name.as_str())
        .collect::<Vec<_>>();

    assert!(
        reads.contains(&"NSProcessInfo.processInfo.arguments"),
        "refs={:?}",
        index.refs
    );
    assert!(
        reads.contains(&"NSProcessInfo.processInfo.environment"),
        "refs={:?}",
        index.refs
    );
}

#[test]
fn block_pointer_type_parameters_do_not_replace_method_parameters() {
    use bonsai_diagnostics::DiagnosticSink;
    use bonsai_lang_api::{AdapterContext, LanguageAdapter};
    use bonsai_vfs::Vfs;
    use parking_lot::RwLock;

    let adapter = bonsai_lang_objc::ObjCAdapter::new();
    let vfs = Vfs::new();
    let file = vfs.write(
        std::path::Path::new("links.m"),
        "@implementation AppDelegate\n- (BOOL)application:(UIApplication *)app continueUserActivity:(NSUserActivity *)userActivity restorationHandler:(void (^)(NSArray *))handler { return YES; }\n@end\n",
    );
    let diagnostics = RwLock::new(DiagnosticSink::default());
    let index = adapter.extract_declarations(
        file,
        &AdapterContext {
            vfs: &vfs,
            diagnostics: &diagnostics,
            tree_provider: None,
            workspace_root: None,
        },
    );
    let method = index
        .defs
        .iter()
        .find(|decl| decl.name == "application")
        .expect("application method");

    assert_eq!(method.params, ["app", "userActivity", "handler"]);
    assert_eq!(
        method.param_annotations,
        [
            vec!["application".to_string()],
            vec!["continueUserActivity".to_string()],
            vec!["restorationHandler".to_string()],
        ]
    );
}

#[test]
fn objc_adapter_emits_function_pointer_callable_alias() {
    use bonsai_diagnostics::DiagnosticSink;
    use bonsai_lang_api::{AdapterContext, FlowEvent, LanguageAdapter};
    use bonsai_vfs::Vfs;
    use parking_lot::RwLock;

    let adapter = bonsai_lang_objc::ObjCAdapter::new();
    let vfs = Vfs::new();
    let file = vfs.write(
        std::path::Path::new("callbacks.m"),
        "void helper(NSString *p) { sink(p); }\nvoid entry(NSString *args) { void (*cb)(NSString*) = helper; cb(args); }\n",
    );
    let diagnostics = RwLock::new(DiagnosticSink::default());
    let ctx = AdapterContext {
        vfs: &vfs,
        diagnostics: &diagnostics,
        tree_provider: None,
        workspace_root: None,
    };
    let idx = adapter.extract_declarations(file, &ctx);
    let entry = idx
        .defs
        .iter()
        .find(|decl| decl.name == "entry")
        .expect("entry decl present");

    assert!(
        entry.flow_events.iter().any(|event| matches!(
            event,
            FlowEvent::Assign {
                target,
                source_name: Some(source),
                source_call: None,
                ..
            } if target == "cb" && source == "helper"
        )),
        "function-pointer initializer must emit exact cb -> helper alias, got {:?}",
        entry.flow_events
    );
}

#[test]
fn objc_block_literal_decl_uses_local_binding_name() {
    use bonsai_diagnostics::DiagnosticSink;
    use bonsai_lang_api::{AdapterContext, FlowEvent, LanguageAdapter};
    use bonsai_vfs::Vfs;
    use parking_lot::RwLock;

    let adapter = bonsai_lang_objc::ObjCAdapter::new();
    let vfs = Vfs::new();
    let file = vfs.write(
        std::path::Path::new("blocks.m"),
        "void entry(NSString *args) { void (^f)(NSString *) = ^(NSString *x) { sink(x); }; f(args); }\n",
    );
    let diagnostics = RwLock::new(DiagnosticSink::default());
    let ctx = AdapterContext {
        vfs: &vfs,
        diagnostics: &diagnostics,
        tree_provider: None,
        workspace_root: None,
    };
    let idx = adapter.extract_declarations(file, &ctx);
    let block = idx.defs.iter().find(|decl| decl.name == "f").unwrap_or_else(|| {
        panic!(
            "block literal must be indexed as local binding `f`; defs: {:?}",
            idx.defs
        )
    });

    assert_eq!(block.params, ["x"]);
    assert!(
        block.flow_events.iter().any(|event| matches!(
            event,
            FlowEvent::Call { name, .. } if name == "sink"
        )),
        "block literal declaration must own sink(x); got {:?}",
        block.flow_events
    );
}

#[test]
fn objc_message_assignment_preserves_ast_call_and_argument_facts() {
    use bonsai_diagnostics::DiagnosticSink;
    use bonsai_lang_api::{AdapterContext, FlowEvent, LanguageAdapter};
    use bonsai_vfs::Vfs;
    use parking_lot::RwLock;

    let adapter = bonsai_lang_objc::ObjCAdapter::new();
    let vfs = Vfs::new();
    let file = vfs.write(
        std::path::Path::new("format.m"),
        "void entry(NSString *value) { NSString *cmd = [NSString stringWithFormat:@\"prefix %@\", value]; sink(cmd); }\n",
    );
    let diagnostics = RwLock::new(DiagnosticSink::default());
    let ctx = AdapterContext {
        vfs: &vfs,
        diagnostics: &diagnostics,
        tree_provider: None,
        workspace_root: None,
    };
    let idx = adapter.extract_declarations(file, &ctx);
    let entry = idx
        .defs
        .iter()
        .find(|decl| decl.name == "entry")
        .expect("entry decl present");

    assert!(
        entry.flow_events.iter().any(|event| matches!(
            event,
            FlowEvent::Assign {
                target,
                source_call: Some(source_call),
                source_call_args,
                ..
            } if target == "cmd"
                && source_call == "NSString.stringWithFormat"
                && source_call_args.iter().any(|arg| arg == "value")
        )),
        "assignment must retain the AST-derived call identity and arguments: {:?}",
        entry.flow_events
    );
    assert!(
        entry.flow_events.iter().any(|event| matches!(
            event,
            FlowEvent::Call { name, args, .. }
                if name == "NSString.stringWithFormat"
                    && args.iter().any(|arg| arg.value_text == "value")
        )),
        "message expression must remain a semantic call fact for resolver/rule models: {:?}",
        entry.flow_events
    );
}

#[test]
fn objc_sibling_project_classes_do_not_share_module_identity() {
    use bonsai_diagnostics::DiagnosticSink;
    use bonsai_lang_api::{AdapterContext, LanguageAdapter, ModulePath};
    use bonsai_vfs::Vfs;
    use parking_lot::RwLock;

    let adapter = bonsai_lang_objc::ObjCAdapter::new();
    let vfs = Vfs::new();
    let root = std::env::temp_dir().join("bonsai-objc-sibling-projects");
    let first = vfs.write(
        root.join("flow_a/Storage.m"),
        "@interface Repository : NSObject\n@end\n@implementation Repository\n@end\n",
    );
    let second = vfs.write(
        root.join("flow_b/Storage.m"),
        "@interface Repository : NSObject\n@end\n@implementation Repository\n@end\n",
    );
    let diagnostics = RwLock::new(DiagnosticSink::default());
    let ctx = AdapterContext {
        vfs: &vfs,
        diagnostics: &diagnostics,
        tree_provider: None,
        workspace_root: Some(&root),
    };

    let first_idx = adapter.extract_declarations(first, &ctx);
    let second_idx = adapter.extract_declarations(second, &ctx);
    let first_repo = first_idx
        .defs
        .iter()
        .find(|decl| decl.name == "Repository")
        .expect("first Repository declaration");
    let second_repo = second_idx
        .defs
        .iter()
        .find(|decl| decl.name == "Repository")
        .expect("second Repository declaration");

    assert_eq!(
        first_repo.module_path,
        ModulePath::from_segments(["flow_a", "Repository"])
    );
    assert_eq!(
        second_repo.module_path,
        ModulePath::from_segments(["flow_b", "Repository"])
    );
    assert_ne!(first_repo.module_path, second_repo.module_path);
}

#[test]
fn objc_inheritance_and_local_receiver_type_are_ast_facts() {
    use bonsai_diagnostics::DiagnosticSink;
    use bonsai_lang_api::{AdapterContext, FlowEvent, LanguageAdapter};
    use bonsai_vfs::Vfs;
    use parking_lot::RwLock;

    let adapter = bonsai_lang_objc::ObjCAdapter::new();
    let vfs = Vfs::new();
    let file = vfs.write(
        std::path::Path::new("Entry.m"),
        "@interface Base : NSObject\n@end\n\
         @interface Child : Base\n@end\n\
         @implementation Child\n@end\n\
         void entry(NSString *args) { Child *obj = [[Child alloc] init]; [obj helper:args]; }\n",
    );
    let diagnostics = RwLock::new(DiagnosticSink::default());
    let ctx = AdapterContext {
        vfs: &vfs,
        diagnostics: &diagnostics,
        tree_provider: None,
        workspace_root: None,
    };
    let idx = adapter.extract_declarations(file, &ctx);
    let child_decls = idx
        .defs
        .iter()
        .filter(|decl| decl.name == "Child")
        .collect::<Vec<_>>();
    assert_eq!(
        child_decls.len(),
        2,
        "interface and implementation are distinct CST declarations"
    );
    assert!(
        child_decls
            .iter()
            .all(|decl| decl.bases.iter().any(|base| base == "Base")),
        "both split declarations must retain the interface's exact superclass: {child_decls:#?}"
    );

    let entry = idx
        .defs
        .iter()
        .find(|decl| decl.name == "entry")
        .expect("entry declaration");
    assert!(
        entry
            .type_aliases
            .iter()
            .any(|alias| alias.name == "obj" && alias.type_name == "Child"),
        "typed local declaration must lower to obj: Child: {:?}",
        entry.type_aliases
    );
    assert!(
        entry.flow_events.iter().any(|event| matches!(
            event,
            FlowEvent::Call {
                name,
                receiver: Some(receiver),
                ..
            } if name == "obj.helper" && receiver == "obj"
        )),
        "message send must retain its receiver and selector: {:?}",
        entry.flow_events
    );
}

#[test]
fn lowercase_declared_class_allocation_is_not_filtered_by_convention() {
    use bonsai_diagnostics::DiagnosticSink;
    use bonsai_lang_api::{AdapterContext, FlowEvent, LanguageAdapter};
    use bonsai_vfs::Vfs;
    use parking_lot::RwLock;

    let adapter = bonsai_lang_objc::ObjCAdapter::new();
    let vfs = Vfs::new();
    let file = vfs.write(
        std::path::Path::new("Entry.m"),
        "@interface lower : NSObject\n- (instancetype)init;\n- (void)run:(NSString *)value;\n@end\n\
         @implementation lower\n- (instancetype)init { return self; }\n- (void)run:(NSString *)value {}\n@end\n\
         void entry(NSString *value) { lower *item = [[lower alloc] init]; [item run:value]; }\n",
    );
    let diagnostics = RwLock::new(DiagnosticSink::default());
    let ctx = AdapterContext {
        vfs: &vfs,
        diagnostics: &diagnostics,
        tree_provider: None,
        workspace_root: None,
    };
    let idx = adapter.extract_declarations(file, &ctx);
    let entry = idx
        .defs
        .iter()
        .find(|decl| decl.name == "entry")
        .expect("entry declaration");
    assert!(
        entry.flow_events.iter().any(|event| matches!(
            event,
            FlowEvent::Call { receiver_types, .. }
                if receiver_types.iter().any(|type_name| type_name == "lower")
        )),
        "events: {:#?}",
        entry.flow_events
    );
}

#[test]
fn objc_message_compound_argument_uses_ast_place_and_sources() {
    use bonsai_diagnostics::DiagnosticSink;
    use bonsai_lang_api::{AdapterContext, FlowEvent, LanguageAdapter};
    use bonsai_vfs::Vfs;
    use parking_lot::RwLock;

    let adapter = bonsai_lang_objc::ObjCAdapter::new();
    let vfs = Vfs::new();
    let file = vfs.write(
        std::path::Path::new("message_args.m"),
        "struct Envelope { NSString *command; };\nvoid entry(id runner, struct Envelope *env) { [runner execute:env->command]; }\n",
    );
    let diagnostics = RwLock::new(DiagnosticSink::default());
    let ctx = AdapterContext {
        vfs: &vfs,
        diagnostics: &diagnostics,
        tree_provider: None,
        workspace_root: None,
    };
    let idx = adapter.extract_declarations(file, &ctx);
    let entry = idx
        .defs
        .iter()
        .find(|decl| decl.name == "entry")
        .expect("entry decl");
    let arg = entry.flow_events.iter().find_map(|event| match event {
        FlowEvent::Call { args, .. } => args.iter().find(|arg| arg.value_text.contains("env->command")),
        _ => None,
    });
    let arg = arg.unwrap_or_else(|| panic!("Objective-C message argument: {:?}", entry.flow_events));
    assert_eq!(arg.place.as_deref(), Some("env.command"));
    assert!(
        arg.source_names.iter().any(|source| source == "env.command"),
        "message argument must expose its AST field carrier: {arg:?}"
    );
}

#[test]
fn fast_enumeration_uses_the_declarator_and_iterable_ast_roles() {
    use bonsai_diagnostics::DiagnosticSink;
    use bonsai_lang_api::{AdapterContext, FlowEvent, LanguageAdapter, LoopKind};
    use bonsai_vfs::Vfs;
    use parking_lot::RwLock;

    let adapter = bonsai_lang_objc::ObjCAdapter::new();
    let vfs = Vfs::new();
    let file = vfs.write(
        std::path::Path::new("fast_enumeration.m"),
        "void entry(NSArray *rows) { for (NSString *row in rows) { sink(row); } }\n",
    );
    let diagnostics = RwLock::new(DiagnosticSink::default());
    let index = adapter.extract_declarations(
        file,
        &AdapterContext {
            vfs: &vfs,
            diagnostics: &diagnostics,
            tree_provider: None,
            workspace_root: None,
        },
    );
    let entry = index
        .defs
        .iter()
        .find(|decl| decl.name == "entry")
        .expect("entry declaration");

    assert!(
        entry.flow_events.iter().any(|event| matches!(
            event,
            FlowEvent::Assign {
                target,
                source_name: Some(source),
                source_names,
                ..
            } if target == "row" && source == "rows" && source_names == &["rows"]
        )),
        "fast enumeration must lower row <- rows without treating NSString as a value: {:#?}",
        entry.flow_events
    );
    assert!(
        !entry.flow_events.iter().any(|event| matches!(
            event,
            FlowEvent::Assign { target, .. } if target == "NSString"
        )),
        "the declared element type is not an iteration binding: {:#?}",
        entry.flow_events
    );
    assert!(
        entry.flow_events.iter().any(|event| matches!(
            event,
            FlowEvent::Loop {
                loop_kind: LoopKind::ForEach,
                ..
            }
        )),
        "fast enumeration must retain foreach control-flow semantics: {:#?}",
        entry.flow_events
    );
}
