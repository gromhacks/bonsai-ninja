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
