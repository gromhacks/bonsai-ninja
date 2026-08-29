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
fn catch_bindings_stay_attached_to_the_exact_objc_handler_arm() {
    use bonsai_lang_api::FlowEvent;

    let workspace = bonsai_testkit::workspace_with(
        vec![Arc::new(bonsai_lang_objc::ObjCAdapter::new())],
        &[(
            "Exceptions.m",
            r#"
void handle(NSString *value) {
  @try { @throw value; }
  @catch (NSString *first) { sink(first); }
  @catch (NSException *second) { audit(second); }
}
"#,
        )],
    );
    let file = workspace.db().vfs().all_files()[0];
    let index = workspace
        .db()
        .decl_index(file)
        .expect("Objective-C compiler index");
    let handle = index
        .defs
        .iter()
        .find(|decl| decl.name == "handle")
        .expect("handle");
    let (aggregate, arms) = handle
        .flow_events
        .iter()
        .find_map(|event| match event {
            FlowEvent::Try {
                catch_param,
                catch_arms,
                ..
            } => Some((catch_param.as_deref(), catch_arms)),
            _ => None,
        })
        .expect("try event");
    assert_eq!(aggregate, Some("first"));
    assert_eq!(
        arms.iter()
            .map(|arm| arm.parameter.as_deref())
            .collect::<Vec<_>>(),
        [Some("first"), Some("second")],
        "each parsed @catch must retain its own binding: {arms:#?}"
    );
    assert!(arms
        .iter()
        .all(|arm| !matches!(arm.parameter.as_deref(), Some("NSString" | "NSException"))));
}

#[test]
fn categories_use_class_nodes_and_keep_method_parentage() {
    use bonsai_lang_api::DeclKind;

    let workspace = bonsai_testkit::workspace_with(
        vec![Arc::new(bonsai_lang_objc::ObjCAdapter::new())],
        &[(
            "Categories.m",
            "@interface Client (Extras)\n- (void)consume:(NSString *)value;\n@end\n@implementation Client (Extras)\n- (void)consume:(NSString *)value { }\n@end\n",
        )],
    );
    let file = workspace.vfs().all_files()[0];
    let index = workspace
        .db()
        .decl_index(file)
        .expect("Objective-C declaration index");
    let owners = index
        .defs
        .iter()
        .filter(|decl| decl.name == "Client" && decl.kind == DeclKind::Class)
        .map(|decl| decl.symbol)
        .collect::<Vec<_>>();
    assert_eq!(owners.len(), 2, "declarations={:#?}", index.defs);
    assert!(
        index.defs.iter().any(|decl| {
            decl.name == "consume"
                && decl.kind == DeclKind::Method
                && decl.parent.is_some_and(|parent| owners.contains(&parent))
                && decl.params == ["value"]
        }),
        "category method lost its class parent or exact parameter: {:#?}",
        index.defs
    );
}

#[test]
fn interface_method_prototype_and_implementation_keep_distinct_syntax_roles() {
    use bonsai_lang_api::{DeclKind, FlowEvent};

    let workspace = bonsai_testkit::workspace_with(
        vec![Arc::new(bonsai_lang_objc::ObjCAdapter::new())],
        &[(
            "Repository.m",
            r#"
@interface Repository : NSObject
- (NSString *)cmd;
@end

@implementation Repository
- (NSString *)cmd { return self.value; }
- (NSString *)run { return [self cmd]; }
@end
"#,
        )],
    );
    let file = workspace.vfs().all_files()[0];
    let index = workspace
        .db()
        .decl_index(file)
        .expect("Objective-C declaration index");
    let commands = index
        .defs
        .iter()
        .filter(|decl| decl.name == "cmd" && decl.kind == DeclKind::Method)
        .collect::<Vec<_>>();
    assert_eq!(
        commands.len(),
        2,
        "prototype and definition syntax must both survive"
    );
    let executable = commands
        .iter()
        .filter(|decl| decl.body_span.is_some() || !decl.flow_events.is_empty())
        .copied()
        .collect::<Vec<_>>();
    assert_eq!(
        executable.len(),
        1,
        "only the implementation is executable: {commands:#?}"
    );
    assert!(
        executable[0]
            .flow_events
            .iter()
            .any(|event| matches!(event, FlowEvent::Return { .. })),
        "the retained callable must be the implementation body: {:#?}",
        executable[0]
    );
    let run = index
        .defs
        .iter()
        .find(|decl| decl.name == "run" && decl.kind == DeclKind::Method)
        .expect("run implementation");
    assert!(
        run.flow_events.iter().any(|event| matches!(
            event,
            FlowEvent::Call { name, .. } if name == "self.cmd"
        )),
        "message dispatch must retain the exact implementation selector: {run:#?}"
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
fn framework_imports_expose_public_bindings_but_project_headers_stay_exact() {
    use bonsai_diagnostics::DiagnosticSink;
    use bonsai_lang_api::{AdapterContext, LanguageAdapter};
    use bonsai_vfs::Vfs;
    use parking_lot::RwLock;

    let adapter = bonsai_lang_objc::ObjCAdapter::new();
    let vfs = Vfs::new();
    let file = vfs.write(
        std::path::Path::new("Imports.m"),
        "#import <WebKit/WebKit.h>\n#import \"LocalService.h\"\n",
    );
    let diagnostics = RwLock::new(DiagnosticSink::default());
    let imports = adapter.extract_imports(
        file,
        &AdapterContext {
            vfs: &vfs,
            diagnostics: &diagnostics,
            tree_provider: None,
            workspace_root: None,
        },
    );

    assert!(imports
        .imports
        .iter()
        .any(|import| import.module == "WebKit/WebKit.h" && import.is_wildcard));
    assert!(imports
        .imports
        .iter()
        .any(|import| import.module == "LocalService.h" && !import.is_wildcard));
}

#[test]
fn url_component_rejection_guard_keeps_exact_boolean_and_call_facts() {
    use bonsai_lang_api::{ConditionExpressionFact, StaticScalarValue};

    let workspace = bonsai_testkit::workspace_with(
        vec![Arc::new(bonsai_lang_objc::ObjCAdapter::new())],
        &[(
            "Guard.m",
            r#"
+ (NSSet *)allowedHosts {
  static NSSet *hosts;
  static dispatch_once_t once;
  dispatch_once(&once, ^{
    hosts = [NSSet setWithObjects:@"api.example", @"webhooks.example", nil];
  });
  return hosts;
}
+ (void)fetch:(NSString *)raw {
  NSURL *url = [NSURL URLWithString:raw];
  if (![url.scheme isEqualToString:@"https"] || ![[self allowedHosts] containsObject:url.host]) {
    return;
  }
  consume(url);
}
"#,
        )],
    );
    let file = workspace.vfs().all_files()[0];
    let index = workspace
        .db()
        .decl_index(file)
        .expect("Objective-C declaration index");
    assert!(matches!(
        index.branch_conditions.as_slice(),
        [fact]
            if matches!(
                fact.expression.as_ref(),
                Some(ConditionExpressionFact::Any { operands, .. })
                    if matches!(operands.as_slice(), [ConditionExpressionFact::Not { .. }, ConditionExpressionFact::Not { .. }])
            )
    ));
    assert!(index.call_receivers.iter().any(|fact| {
        fact.value_flow
            .projection
            .as_ref()
            .is_some_and(|projection| projection.base == "url" && projection.path == ["scheme"])
    }));
    assert!(index
        .call_receivers
        .iter()
        .any(|fact| { fact.value_flow.place.is_none() && fact.value_flow.call_sites.len() == 1 }));
    assert!(index.call_argument_values.iter().any(|fact| {
        matches!(fact.static_value.as_ref(), Some(StaticScalarValue::String(value)) if value == "https")
    }));
    let hosts = index
        .assignment_values
        .iter()
        .find(|fact| fact.target.as_deref() == Some("hosts"))
        .expect("static host-set assignment");
    assert_eq!(hosts.direct_call_name.as_deref(), Some("NSSet.setWithObjects"));
    assert!(matches!(
        hosts.exact_static_call_args.as_deref(),
        Some([
            StaticScalarValue::String(first),
            StaticScalarValue::String(second),
            StaticScalarValue::Null,
        ]) if first == "api.example" && second == "webhooks.example"
    ));
}

#[test]
fn objc_call_arguments_retain_exact_static_scalars_without_guessing_dynamic_values() {
    use bonsai_diagnostics::DiagnosticSink;
    use bonsai_lang_api::{AdapterContext, LanguageAdapter, StaticScalarValue};
    use bonsai_vfs::Vfs;
    use parking_lot::RwLock;

    let adapter = bonsai_lang_objc::ObjCAdapter::new();
    let vfs = Vfs::new();
    let file = vfs.write(
        std::path::Path::new("literal_facts.m"),
        r#"
void run(id receiver, id dynamicValue) {
  NSString *exactAssignment = @"fixed";
  id dynamicAssignment = dynamicValue;
  [receiver combine:@"/" escaped:@"line\n" character:'x' dynamic:dynamicValue];
}
"#,
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
    let run = index
        .defs
        .iter()
        .find(|decl| decl.name == "run")
        .expect("run declaration");
    let call_span = run
        .flow_events
        .iter()
        .find_map(|event| match event {
            bonsai_lang_api::FlowEvent::Call { name, span, .. }
                if name == "receiver.combine:escaped:character:dynamic:" =>
            {
                Some(*span)
            }
            _ => None,
        })
        .expect("complete multipart call");
    let value = |argument_index| {
        index
            .call_argument_values
            .iter()
            .find(|fact| fact.call_span == call_span && fact.argument_index == argument_index)
            .and_then(|fact| fact.static_value.clone())
    };
    assert_eq!(value(0), Some(StaticScalarValue::String("/".to_string())));
    assert_eq!(value(1), Some(StaticScalarValue::String("line\n".to_string())));
    assert_eq!(value(2), Some(StaticScalarValue::String("x".to_string())));
    assert_eq!(value(3), None, "dynamic arguments must remain unclassified");
    let assigned_value = |target: &str| {
        index
            .assignment_values
            .iter()
            .find(|fact| fact.target.as_deref() == Some(target))
            .and_then(|fact| fact.static_value.clone())
    };
    assert_eq!(
        assigned_value("exactAssignment"),
        Some(StaticScalarValue::String("fixed".to_string()))
    );
    assert_eq!(
        assigned_value("dynamicAssignment"),
        None,
        "a dynamic assignment RHS must not acquire a static scalar"
    );
}

#[test]
fn multipart_message_sends_keep_the_complete_selector_identity() {
    use bonsai_diagnostics::DiagnosticSink;
    use bonsai_lang_api::{AdapterContext, FlowEvent, LanguageAdapter};
    use bonsai_vfs::Vfs;
    use parking_lot::RwLock;

    let adapter = bonsai_lang_objc::ObjCAdapter::new();
    let vfs = Vfs::new();
    let file = vfs.write(
        std::path::Path::new("selectors.m"),
        r#"
void execute(id db, id values) {
  [db executeUpdate:@"insert" withParameterDictionary:values];
  [db executeUpdate:@"insert" withArgumentsInArray:values];
  [db close];
}

@interface Store
- (void)executeUpdate:(id)sql withParameterDictionary:(id)values;
- (void)executeUpdate:(id)sql withArgumentsInArray:(id)values;
@end

@implementation Store
- (void)executeUpdate:(id)sql withParameterDictionary:(id)values { }
- (void)executeUpdate:(id)sql withArgumentsInArray:(id)values { }
@end
"#,
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
    let execute = index
        .defs
        .iter()
        .find(|decl| decl.name == "execute")
        .expect("execute declaration");
    let calls = execute
        .flow_events
        .iter()
        .filter_map(|event| match event {
            FlowEvent::Call { name, args, .. } => Some((name.as_str(), args.len())),
            _ => None,
        })
        .collect::<Vec<_>>();

    assert!(
        calls.contains(&("db.executeUpdate:withParameterDictionary:", 2)),
        "calls={calls:#?}"
    );
    assert!(
        calls.contains(&("db.executeUpdate:withArgumentsInArray:", 2)),
        "selector collision was collapsed: {calls:#?}"
    );
    assert!(
        calls.contains(&("db.close", 0)),
        "one-keyword messages must retain their established identity: {calls:#?}"
    );

    let selector_identities = index
        .defs
        .iter()
        .filter(|decl| decl.name == "executeUpdate")
        .filter_map(|decl| {
            decl.qualified_name
                .as_deref()
                .and_then(|qualified| bonsai_common::declaration_qualified_suffix(&decl.name, qualified))
        })
        .collect::<Vec<_>>();
    assert_eq!(
        selector_identities.len(),
        4,
        "prototype/definition identities: {:#?}",
        index.defs
    );
    for expected in [
        "executeUpdate:withParameterDictionary:",
        "executeUpdate:withArgumentsInArray:",
    ] {
        assert_eq!(
            selector_identities
                .iter()
                .filter(|identity| **identity == expected)
                .count(),
            2,
            "prototype and implementation must share exact selector identity: {selector_identities:#?}"
        );
    }
    assert_eq!(
        index
            .defs
            .iter()
            .filter(|decl| decl.name == "executeUpdate" && decl.body_span.is_some())
            .count(),
        2,
        "only the two implementations may carry executable bodies"
    );
}

#[test]
fn imported_multipart_selector_resolves_to_the_executable_implementation() {
    use bonsai_common::FuncId;

    let workspace = bonsai_testkit::workspace_with(
        vec![Arc::new(bonsai_lang_objc::ObjCAdapter::new())],
        &[
            (
                "AuthService.h",
                r#"
@interface AuthService
- (void)runAdminCommand:(id)userId action:(id)action;
@end
"#,
            ),
            (
                "AuthService.m",
                r#"
#import "AuthService.h"
@implementation AuthService
- (void)runAdminCommand:(id)userId action:(id)action { consume(action); }
@end
"#,
            ),
            (
                "UserService.h",
                r#"
#import "AuthService.h"
@interface UserService
- (void)updateUser:(id)action;
@end
"#,
            ),
            (
                "UserService.m",
                r#"
#import "UserService.h"
@implementation UserService
- (void)updateUser:(id)action {
  AuthService *auth = [[AuthService alloc] init];
  [auth runAdminCommand:@1 action:action];
}
@end
"#,
            ),
        ],
    );
    let global = workspace.db().global_index();
    let caller = global
        .all_files()
        .flat_map(|file| global.functions_in(file))
        .find(|decl| decl.name == "updateUser" && decl.body_span.is_some())
        .expect("updateUser implementation");
    let target = global
        .all_files()
        .flat_map(|file| global.functions_in(file))
        .find(|decl| decl.name == "runAdminCommand" && decl.body_span.is_some())
        .expect("runAdminCommand implementation");
    let prototypes = global
        .all_files()
        .flat_map(|file| global.functions_in(file))
        .filter(|decl| decl.name == "runAdminCommand" && decl.body_span.is_none())
        .map(|decl| FuncId::new(decl.symbol.raw()))
        .collect::<Vec<_>>();
    assert_eq!(
        prototypes.len(),
        1,
        "header prototype must remain compiler-visible"
    );

    let graph = workspace.resolved_call_graph();
    let callees = graph
        .callees_of(FuncId::new(caller.symbol.raw()))
        .map(|edge| edge.to)
        .collect::<Vec<_>>();
    assert!(
        callees.contains(&FuncId::new(target.symbol.raw())),
        "typed header dispatch must link the exact selector to its body: {callees:?}"
    );
    assert!(
        prototypes.iter().all(|prototype| !callees.contains(prototype)),
        "a bodyless prototype must not replace its implementation target: {callees:?}"
    );
}

#[test]
fn imported_initializer_resolves_to_definition_and_keeps_prototype_bodyless() {
    use bonsai_common::FuncId;
    use bonsai_lang_api::DeclKind;

    let workspace = bonsai_testkit::workspace_with(
        vec![Arc::new(bonsai_lang_objc::ObjCAdapter::new())],
        &[
            (
                "Repository.h",
                r#"
@interface Repository : NSObject
- (instancetype)initWithData:(id)data;
@end
"#,
            ),
            (
                "Repository.m",
                r#"
#import "Repository.h"
@implementation Repository
- (instancetype)initWithData:(id)data {
  self = [super init];
  if (self) { _data = data; }
  return self;
}
@end
"#,
            ),
            (
                "Service.m",
                r#"
#import "Repository.h"
id persist(id input) {
  Repository *repo = [[Repository alloc] initWithData:input];
  return repo;
}
"#,
            ),
        ],
    );
    let global = workspace.db().global_index();
    let constructors = global
        .all_files()
        .flat_map(|file| global.functions_in(file))
        .filter(|decl| decl.kind == DeclKind::Constructor && decl.name == "initWithData")
        .collect::<Vec<_>>();
    assert_eq!(
        constructors.len(),
        2,
        "header and implementation must both remain compiler-visible: {constructors:#?}"
    );
    let prototype = constructors
        .iter()
        .copied()
        .find(|decl| decl.body_span.is_none())
        .expect("bodyless initializer prototype");
    let implementation = constructors
        .iter()
        .copied()
        .find(|decl| decl.body_span.is_some())
        .expect("executable initializer implementation");
    assert_eq!(
        bonsai_common::declaration_qualified_suffix(
            &prototype.name,
            prototype.qualified_name.as_deref().expect("prototype identity"),
        ),
        bonsai_common::declaration_qualified_suffix(
            &implementation.name,
            implementation
                .qualified_name
                .as_deref()
                .expect("implementation identity"),
        ),
        "prototype and definition must share the exact selector identity"
    );

    let caller = global
        .all_files()
        .flat_map(|file| global.functions_in(file))
        .find(|decl| decl.name == "persist")
        .expect("persist caller");
    let graph = workspace.resolved_call_graph();
    let callees = graph
        .callees_of(FuncId::new(caller.symbol.raw()))
        .map(|edge| edge.to)
        .collect::<Vec<_>>();
    assert!(
        callees.contains(&FuncId::new(implementation.symbol.raw())),
        "constructor call must resolve to executable definition: callees={callees:?}, caller={caller:#?}, constructors={constructors:#?}"
    );
    assert!(
        !callees.contains(&FuncId::new(prototype.symbol.raw())),
        "bodyless prototype must not replace the definition: {callees:?}"
    );
}

#[test]
fn value_binding_shadowing_a_class_name_is_not_constructor_evidence() {
    use bonsai_diagnostics::DiagnosticSink;
    use bonsai_lang_api::{AdapterContext, CallKind, FlowEvent, LanguageAdapter};
    use bonsai_vfs::Vfs;
    use parking_lot::RwLock;

    let adapter = bonsai_lang_objc::ObjCAdapter::new();
    let vfs = Vfs::new();
    let file = vfs.write(
        std::path::Path::new("shadow.m"),
        r#"
void run(id input) {
  id Repository = input;
  id value = [[Repository alloc] initWithData:input];
}
"#,
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
    let run = index
        .defs
        .iter()
        .find(|decl| decl.name == "run")
        .expect("run declaration");
    let (kind, receiver_types) = run
        .flow_events
        .iter()
        .find_map(|event| match event {
            FlowEvent::Call {
                name,
                call_kind,
                receiver_types,
                ..
            } if name.ends_with("initWithData") => Some((*call_kind, receiver_types)),
            _ => None,
        })
        .expect("nested message call");
    assert_eq!(kind, CallKind::Method);
    assert!(
        receiver_types.is_empty(),
        "a local value receiver must not be promoted into a class type: {receiver_types:?}"
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
fn source_boundary_selector_parameters_keep_exact_piece_annotations() {
    use bonsai_diagnostics::DiagnosticSink;
    use bonsai_lang_api::{AdapterContext, LanguageAdapter};
    use bonsai_vfs::Vfs;
    use parking_lot::RwLock;

    let adapter = bonsai_lang_objc::ObjCAdapter::new();
    let vfs = Vfs::new();
    let file = vfs.write(
        std::path::Path::new("delegates.m"),
        r#"
@implementation Client
- (void)URLSession:(NSURLSession *)session dataTask:(NSURLSessionDataTask *)task didReceiveData:(NSData *)chunk { }
- (void)URLSession:(NSURLSession *)session downloadTask:(NSURLSessionDownloadTask *)task didFinishDownloadingToURL:(NSURL *)location { }
- (void)URLSession:(NSURLSession *)session task:(NSURLSessionTask *)task willPerformHTTPRedirection:(NSHTTPURLResponse *)response newRequest:(NSURLRequest *)redirected completionHandler:(void (^)(NSURLRequest *))completion { }
@end
"#,
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

    let annotation_for = |param: &str| {
        index.defs.iter().find_map(|decl| {
            decl.params
                .iter()
                .position(|candidate| candidate == param)
                .and_then(|idx| decl.param_annotations.get(idx))
                .cloned()
        })
    };
    assert_eq!(annotation_for("chunk"), Some(vec!["didReceiveData".to_string()]));
    assert_eq!(
        annotation_for("location"),
        Some(vec!["didFinishDownloadingToURL".to_string()])
    );
    assert_eq!(annotation_for("redirected"), Some(vec!["newRequest".to_string()]));
    for (param, expected_type) in [
        ("chunk", "NSData"),
        ("location", "NSURL"),
        ("redirected", "NSURLRequest"),
    ] {
        let aliases = index
            .defs
            .iter()
            .filter(|decl| decl.params.iter().any(|candidate| candidate == param))
            .map(|decl| (&decl.name, &decl.params, &decl.type_aliases))
            .collect::<Vec<_>>();
        assert!(
            index.defs.iter().any(|decl| {
                decl.params.iter().any(|candidate| candidate == param)
                    && decl
                        .type_aliases
                        .iter()
                        .any(|alias| alias.name == param && alias.type_name == expected_type)
            }),
            "missing {param}: {expected_type} alias; aliases={aliases:#?}"
        );
    }
}

#[test]
fn objective_c_blocks_are_exact_call_argument_callback_facts() {
    use bonsai_diagnostics::DiagnosticSink;
    use bonsai_lang_api::{AdapterContext, FlowEvent, LanguageAdapter};
    use bonsai_vfs::Vfs;
    use parking_lot::RwLock;

    let adapter = bonsai_lang_objc::ObjCAdapter::new();
    let vfs = Vfs::new();
    let file = vfs.write(
        std::path::Path::new("callbacks.m"),
        r#"
void load(NSURLSession *session, NSURL *url) {
  [session dataTaskWithURL:url completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
    consume(data);
  }];
}
"#,
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
    let load = index
        .defs
        .iter()
        .find(|decl| decl.name == "load")
        .expect("load declaration");
    let call_span = load
        .flow_events
        .iter()
        .find_map(|event| match event {
            FlowEvent::Call { name, span, .. } if name == "session.dataTaskWithURL:completionHandler:" => {
                Some(*span)
            }
            _ => None,
        })
        .expect("exact URLSession multipart-selector call");
    let callback = index
        .call_argument_values
        .iter()
        .find(|fact| fact.call_span == call_span && fact.argument_index == 1)
        .expect("completion block argument fact");
    assert_eq!(
        callback.inline_callback_params,
        ["data", "response", "error"],
        "callback={callback:#?}"
    );
    assert!(callback.inline_callback_span.is_some());
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

#[test]
fn finite_dictionary_selection_is_local_literal_and_collision_safe() {
    use bonsai_diagnostics::DiagnosticSink;
    use bonsai_lang_api::{AdapterContext, LanguageAdapter};
    use bonsai_vfs::Vfs;
    use parking_lot::RwLock;

    let adapter = bonsai_lang_objc::ObjCAdapter::new();
    let vfs = Vfs::new();
    let file = vfs.write(
        std::path::Path::new("finite_dictionary.m"),
        r#"
NSString *choose_first(NSString *selector) {
  NSDictionary *choices = @{ @"one": @"alpha", @"two": @"beta" };
  return choices[selector] ?: @"fallback";
}

NSString *choose_second(NSString *selector) {
  NSDictionary *choices = @{ @"three": @"gamma", @"four": @"delta" };
  return choices[selector] ?: @"fallback";
}

void consume_choice(NSString *selector) {
  NSDictionary *choices = @{ @"left": @"alpha", @"right": @"beta" };
  NSString *selected = choices[selector] ?: @"fallback";
  consume(selected);
}

void consume_direct_choice(NSString *selector) {
  NSDictionary *choices = @{ @"left": @"alpha", @"right": @"beta" };
  NSString *column = choices[selector];
  consume(column);
}

NSArray *collect_direct_choices(NSArray *selectors) {
  NSDictionary *allowed = @{ @"left": @"alpha", @"right": @"beta" };
  NSMutableArray *out = [NSMutableArray array];
  for (NSString *selector in selectors) {
    NSString *mapped = allowed[selector];
    if (mapped) [out addObject:mapped];
  }
  if (out.count == 0) [out addObject:@"fallback"];
  return out;
}
"#,
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

    let direct_helpers = ["choose_first", "choose_second"]
        .into_iter()
        .map(|name| {
            let decl = index.defs.iter().find(|decl| decl.name == name).expect("helper");
            index
                .finite_literal_selections
                .iter()
                .filter(|fact| {
                    fact.assignment_span.is_none()
                        && fact.call_span.is_none()
                        && decl.span.start <= fact.selection_span.start
                        && fact.selection_span.end <= decl.span.end
                })
                .count()
        })
        .collect::<Vec<_>>();
    assert_eq!(
        direct_helpers,
        [1, 1],
        "same-spelled local maps in independent callables must retain distinct proofs: {:#?}",
        index.finite_literal_selections
    );
    assert!(
        index
            .finite_literal_selections
            .iter()
            .any(|fact| fact.target.as_deref() == Some("selected") && fact.assignment_span.is_some()),
        "a locally assigned exact selection must retain its assignment owner: {:#?}",
        index.finite_literal_selections
    );
    assert!(
        index
            .finite_literal_selections
            .iter()
            .any(|fact| fact.target.as_deref() == Some("column") && fact.assignment_span.is_some()),
        "a direct lookup from one stable literal dictionary must retain an exact finite assignment: {:#?}",
        index.finite_literal_selections
    );
    assert!(
        index
            .finite_literal_selections
            .iter()
            .any(|fact| fact.target.as_deref() == Some("mapped") && fact.assignment_span.is_some()),
        "a direct finite lookup inside a collection loop must retain its exact assignment owner: {:#?}",
        index.finite_literal_selections
    );
}

#[test]
fn finite_dictionary_selection_fails_closed_on_unproven_shapes() {
    use bonsai_diagnostics::DiagnosticSink;
    use bonsai_lang_api::{AdapterContext, LanguageAdapter};
    use bonsai_vfs::Vfs;
    use parking_lot::RwLock;

    let adapter = bonsai_lang_objc::ObjCAdapter::new();
    let vfs = Vfs::new();
    let file = vfs.write(
        std::path::Path::new("finite_dictionary_negative.m"),
        r#"
NSString *dynamic_dictionary_key(NSString *selector) {
  NSDictionary *choices = @{ selector: @"alpha" };
  return choices[selector] ?: @"fallback";
}
NSString *dynamic_dictionary_value(NSString *selector, NSString *runtime) {
  NSDictionary *choices = @{ @"one": runtime };
  return choices[selector] ?: @"fallback";
}
NSString *dynamic_fallback(NSString *selector, NSString *runtime) {
  NSDictionary *choices = @{ @"one": @"alpha" };
  return choices[selector] ?: runtime;
}
NSString *dynamic_direct(NSString *selector, NSString *runtime) {
  NSDictionary *choices = @{ @"one": runtime };
  return choices[selector];
}
NSString *mutated(NSString *selector, NSString *runtime) {
  NSDictionary *choices = @{ @"one": @"alpha" };
  choices[@"one"] = runtime;
  return choices[selector] ?: @"fallback";
}
NSString *reassigned(NSString *selector) {
  NSDictionary *choices = @{ @"one": @"alpha" };
  choices = @{ @"two": @"beta" };
  return choices[selector] ?: @"fallback";
}
NSString *aliased(NSString *selector) {
  NSDictionary *choices = @{ @"one": @"alpha" };
  id other = choices;
  return choices[selector] ?: @"fallback";
}
NSString *escaped(NSString *selector) {
  NSDictionary *choices = @{ @"one": @"alpha" };
  observe(choices);
  return choices[selector] ?: @"fallback";
}
NSString *shadowed(NSString *selector) {
  NSDictionary *choices = @{ @"one": @"alpha" };
  if (selector) {
    NSDictionary *choices = @{ @"two": @"beta" };
    return choices[selector] ?: @"fallback";
  }
  return choices[selector] ?: @"fallback";
}
NSString *incomplete(NSString *selector) {
  NSDictionary *choices = @{ @"one": @"alpha" };
  if (selector) return choices[selector] ?: @"fallback";
  return selector;
}
"#,
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

    assert!(
        index.finite_literal_selections.is_empty(),
        "dynamic literals, mutation, reassignment, shadowing, alias/escape, and incomplete returns must fail closed: {:#?}",
        index.finite_literal_selections
    );
}
