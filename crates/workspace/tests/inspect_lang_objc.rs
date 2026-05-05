#[path = "inspect_harness.rs"]
mod h;

use h::*;
use std::sync::Arc;

fn objc() -> bonsai_lang_api::AdapterArc {
    Arc::new(bonsai_lang_objc::ObjCAdapter::new())
}

#[test]
fn cross_file_chain() {
    let w = ws_multi(
        objc(),
        &[
            (
                "/w/gateway.m",
                "#import \"UserService.h\"\n\
                 void handleRequest(NSString *t) { updateUser(t); }\n",
            ),
            (
                "/w/user_service.m",
                "#import \"Auth.h\"\n\
                 void updateUser(NSString *t) { runAdminCommand(t); }\n",
            ),
            (
                "/w/auth.m",
                "void runAdminCommand(NSString *cmd) { system([cmd UTF8String]); }\n",
            ),
        ],
    );
    assert_chain_from_to(&w, "handleRequest", "runAdminCommand");
}

#[test]
fn chain_through_if_for_while_try() {
    let w = ws_multi(
        objc(),
        &[(
            "/w/a.m",
            "void entry(int x) {\n\
               if (x > 0) { a(); } else { b(); }\n\
               for (int i = 0; i < 3; i++) { step(); }\n\
               while (cond()) { d(); }\n\
               @try { e(); } @catch (NSException *ex) { recover(); } @finally { cleanup(); }\n\
             }\n\
             void a() { sink(); }\n\
             void b() { sink(); }\n\
             void step() { sink(); }\n\
             int cond() { return 0; }\n\
             void d() { sink(); }\n\
             void e() { sink(); }\n\
             void recover() { sink(); }\n\
             void cleanup() { sink(); }\n\
             void sink() {}\n",
        )],
    );
    let chains = enumerate_chains(&w, "sink", 32);
    for via in ["a", "b", "step", "d", "e", "recover", "cleanup"] {
        assert!(
            chains.iter().any(|ch| ch.contains(&via.to_string())),
            "missing {via} path: {chains:?}"
        );
    }
}

#[test]
fn message_send_through_class_instance() {
    let w = ws_multi(
        objc(),
        &[(
            "/w/a.m",
            "@interface Svc : NSObject\n- (void)update:(NSString *)t;\n@end\n\
             @implementation Svc\n- (void)update:(NSString *)t { [self sink:t]; }\n\
             - (void)sink:(NSString *)t {}\n@end\n\
             void entry() { Svc *svc = [[Svc alloc] init]; [svc update:@\"x\"]; }\n",
        )],
    );
    assert_chain_from_to(&w, "entry", "update");
}

#[test]
fn import_is_surfaced_as_import() {
    let w = ws_multi(
        objc(),
        &[(
            "/w/a.m",
            "#import <Foundation/Foundation.h>\n\
             #import \"MyHeader.h\"\n\
             void f() {}\n",
        )],
    );
    assert!(query_hits(&w, "Foundation").has_import("Foundation"));
    assert!(query_hits(&w, "MyHeader").has_import("MyHeader"));
}

#[test]
fn regex_query_on_objc_decls() {
    let w = ws_multi(
        objc(),
        &[(
            "/w/a.m",
            "void runAdminCommand() {}\n\
             void runUserCommand() {}\n\
             void handle() {}\n",
        )],
    );
    let h = query_hits_regex(&w, "^run[A-Z].*Command$");
    assert!(h.has_decl("runAdminCommand"));
    assert!(h.has_decl("runUserCommand"));
}

#[test]
fn inspect_filter_from_to_through_branches() {
    let w = ws_multi(
        objc(),
        &[(
            "/w/a.m",
            "void entry(int c) { if (c > 0) { happy(); } else { recover(); } }\n\
             void happy() { sink(); }\n\
             void recover() { sink(); }\n\
             void sink() {}\n",
        )],
    );
    for via in ["happy", "recover"] {
        assert_filters_keep(
            &w,
            "sink",
            "sink",
            InspectFilters {
                from: Some(via),
                to: Some("sink"),
                ..Default::default()
            },
        );
    }
}

#[test]
fn objc_fuzzy_from_across_node_types() {
    let w = ws_multi(
        objc(),
        &[(
            "/w/h.m",
            "#import <Foundation/Foundation.h>\n\
             void process(NSString *s) {}\n\
             void handleRequest(NSString *q) {\n\
               NSString *requestUrl = @\"/api/request\";\n\
               process(requestUrl);\n\
             }\n",
        )],
    );
    assert_function_named(&w, "handleRequest");
    assert_function_named(&w, "process");
    assert_fuzzy_substring("handleRequest", "req");
    assert_fuzzy_substring("handleRequest", "REQUEST");
    assert_hit_text_match("/api/request", "req");
}

#[test]
fn objc_filter_rejects_unrelated_hits() {
    let w = ws_multi(objc(), &[("/w/m.m", "void entry() { NSLog(@\"hi\"); }\n")]);
    assert_function_named(&w, "entry");
    assert_filter_rejects_unrelated(&w, "entry", "NSLog", "nowhere", "nothere");
}
