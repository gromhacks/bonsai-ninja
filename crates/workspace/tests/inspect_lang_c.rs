#[path = "inspect_harness.rs"]
mod h;

use h::*;
use std::sync::Arc;

fn c() -> bonsai_lang_api::AdapterArc {
    Arc::new(bonsai_lang_c::CAdapter::new())
}

#[test]
fn cross_file_chain() {
    let w = ws_multi(
        c(),
        &[
            (
                "/w/gateway.c",
                "#include \"user_service.h\"\nvoid handle_request(const char* t) { update_user(t); }\n",
            ),
            (
                "/w/user_service.c",
                "#include \"auth.h\"\nvoid update_user(const char* t) { run_admin_command(t); }\n",
            ),
            (
                "/w/auth.c",
                "#include <stdlib.h>\nvoid run_admin_command(const char* cmd) { system(cmd); }\n",
            ),
        ],
    );
    assert_chain_from_to(&w, "handle_request", "run_admin_command");
}

#[test]
fn chain_through_branch_for_while_do() {
    let w = ws_multi(
        c(),
        &[(
            "/w/a.c",
            "void entry(int x, int n) {\n\
               if (x > 0) a(); else b();\n\
               for (int i = 0; i < n; ++i) step(i);\n\
               while (cond()) d();\n\
               do { e(); } while (cond());\n\
             }\nvoid a() { sink(); }\nvoid b() { sink(); }\nvoid step(int i) { sink(); }\nint cond() { return 0; }\nvoid d() { sink(); }\nvoid e() { sink(); }\nvoid sink() {}\n",
        )],
    );
    let chains = enumerate_chains(&w, "sink", 32);
    for via in ["a", "b", "step", "d", "e"] {
        assert!(
            chains.iter().any(|ch| ch.contains(&via.to_string())),
            "missing {via} path: {chains:?}"
        );
    }
}

#[test]
fn include_is_import_query() {
    let w = ws_multi(
        c(),
        &[(
            "/w/a.c",
            "#include <stdio.h>\n#include \"local.h\"\nint main() { return 0; }\n",
        )],
    );
    assert!(query_hits(&w, "stdio").has_import("stdio"));
    assert!(query_hits(&w, "local").has_import("local"));
}

#[test]
fn inspect_filter_from_to_through_for_while() {
    let w = ws_multi(
        c(),
        &[(
            "/w/a.c",
            "void entry(int n) {\n\
               for (int i = 0; i < n; ++i) step(i);\n\
               while (cond()) d();\n\
             }\nvoid step(int i) { sink(); }\nint cond() { return 0; }\nvoid d() { sink(); }\nvoid sink() {}\n",
        )],
    );
    for via in ["step", "d"] {
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

/// Regression: C `function_definition` nodes have no `name` field. The
/// generic extractor used to pick the first identifier-like child, which
/// is the RETURN TYPE (`UserInfo` in `UserInfo *get_user(...)`). The fix
/// prefers the `declarator` subtree before falling back. This test pins
/// that the function is indexed under its real name.
#[test]
fn c_function_name_not_return_type() {
    let w = ws_multi(
        c(),
        &[(
            "/w/user_service.c",
            "typedef struct UserInfo UserInfo;\n\
             UserInfo *get_user(const char *t) {\n\
                 return (UserInfo *)0;\n\
             }\n",
        )],
    );
    assert_function_named(&w, "get_user");
    assert_no_function_named(&w, "UserInfo");
}

/// Regression for the reported bug: `--from malloc --to free` on a file
/// where `malloc` lives in a sibling subtree (`get_user`) and `free` lives
/// in the entry (`handle_request`). Both are reachable from the same
/// entry, so the filter must match via downstream closure.
#[test]
fn c_from_to_filter_across_sibling_subtrees() {
    let w = ws_multi(
        c(),
        &[
            (
                "/w/gateway.c",
                "#include <stdlib.h>\n\
                 #include \"user_service.h\"\n\
                 void handle_request(const char *token) {\n\
                     void *user = get_user(token);\n\
                     free(user);\n\
                 }\n",
            ),
            (
                "/w/user_service.c",
                "#include <stdlib.h>\n\
                 void *get_user(const char *token) {\n\
                     return malloc(32);\n\
                 }\n",
            ),
        ],
    );
    // Pin the name extraction so a regression there doesn't silently
    // mask this filter test.
    assert_function_named(&w, "get_user");
    assert_function_named(&w, "handle_request");
    assert_sibling_flow_filter_keeps(&w, "handle_request", "malloc", "free");
}

/// C `typedef struct { ... } Name;` — the struct is anonymous, the
/// typedef name is a sibling. It must still be indexed as a Struct decl.
#[test]
fn c_typedef_struct_indexed_as_struct() {
    let w = ws_multi(c(), &[("/w/h.c", "typedef struct {\n    int id;\n} User;\n")]);
    // Pass: at least one C Struct-kind declaration named `User`.
    let global = w.db().global_index();
    let hit = global
        .find_by_name("User")
        .iter()
        .filter_map(|s| global.decl_of(*s))
        .any(|d| matches!(d.kind, bonsai_lang_api::DeclKind::Struct));
    assert!(hit, "typedef struct `User` not indexed as Struct");
}

/// No-false-positives: `--from X --to Y` where neither needle connects
/// to the hit's flow must reject. Using a `printf` hit with filter
/// `--from nowhere --to nothere` — the hit text doesn't match either
/// needle and neither appears in the reachable flow.
#[test]
fn c_filter_rejects_unrelated_hits() {
    let w = ws_multi(
        c(),
        &[(
            "/w/main.c",
            "#include <stdio.h>\nvoid entry(void) { printf(\"hi\"); }\n",
        )],
    );
    assert_function_named(&w, "entry");
    assert_filter_rejects_unrelated(&w, "entry", "printf", "nowhere", "nothere");
}
