#[path = "inspect_harness.rs"]
mod h;

use h::*;
use std::sync::Arc;

fn sc() -> bonsai_lang_api::AdapterArc {
    Arc::new(bonsai_lang_scala::ScalaAdapter::new())
}

#[test]
fn cross_object_chain() {
    let w = ws_multi(
        sc(),
        &[
            (
                "/w/Gateway.scala",
                "object Gateway { def handleRequest(t: String): Unit = UserService.updateUser(t) }\n",
            ),
            (
                "/w/UserService.scala",
                "object UserService { def updateUser(t: String): Unit = AuthService.runAdminCommand(t) }\n",
            ),
            (
                "/w/AuthService.scala",
                "object AuthService { def runAdminCommand(cmd: String): Unit = shellOut(cmd)\ndef shellOut(c: String): Unit = () }\n",
            ),
        ],
    );
    assert_chain_from_to(&w, "handleRequest", "runAdminCommand");
}

#[test]
fn chain_through_match_for_try() {
    let w = ws_multi(
        sc(),
        &[(
            "/w/A.scala",
            "object A {\n\
               def entry(x: Int, xs: List[Int]): Unit = {\n\
                 x match { case 0 => a(); case _ => b() }\n\
                 for (v <- xs) step(v)\n\
                 try { d() } catch { case e: Exception => recover() } finally { cleanup() }\n\
               }\n\
               def a(): Unit = sink()\n\
               def b(): Unit = sink()\n\
               def step(v: Int): Unit = sink()\n\
               def d(): Unit = sink()\n\
               def recover(): Unit = sink()\n\
               def cleanup(): Unit = sink()\n\
               def sink(): Unit = ()\n\
             }\n",
        )],
    );
    let chains = enumerate_chains(&w, "sink", 32);
    for via in ["a", "b", "step", "d", "recover", "cleanup"] {
        assert!(
            chains.iter().any(|ch| ch.contains(&via.to_string())),
            "missing {via} path: {chains:?}"
        );
    }
}

#[test]
fn import_brace_alias_and_wildcard() {
    let w = ws_multi(
        sc(),
        &[(
            "/w/A.scala",
            "import scala.collection.{mutable => mut}\nimport scala.util._\nobject A { def f(): Unit = () }\n",
        )],
    );
    assert!(query_hits(&w, "scala.collection").has_import("scala.collection"));
    assert!(query_hits(&w, "scala.util").has_import("scala.util"));
}

#[test]
fn annotation_matches_decorator() {
    let w = ws_multi(
        sc(),
        &[("/w/A.scala", "object A { @deprecated def f(): Unit = () }\n")],
    );
    assert!(query_hits(&w, "deprecated").has_decorator("deprecated"));
}

#[test]
fn inspect_filter_resolves_scala_brace_arrow_alias() {
    // `import x.{mutable => mut}; mut()` — caller-map indexes under
    // both the alias `mut` AND the original `mutable`.
    let w = ws_multi(
        sc(),
        &[(
            "/w/A.scala",
            "object M { def mutable(): Unit = () }\n\
             import M.{mutable => mut}\n\
             object A { def handle(): Unit = mut() }\n",
        )],
    );
    let chains = enumerate_chains(&w, "mutable", 32);
    assert!(
        chains.iter().any(|c| c.iter().any(|h| h == "handle")),
        "Scala rename chain missing: {chains:?}"
    );
}

#[test]
fn inspect_filter_from_to_through_match_expr() {
    let w = ws_multi(
        sc(),
        &[(
            "/w/A.scala",
            "object A {\n\
               def entry(x: Int): Int = x match { case 0 => 1; case _ => downstream() }\n\
               def downstream(): Int = sink()\n\
               def sink(): Int = 0\n\
             }\n",
        )],
    );
    assert_filters_keep(
        &w,
        "sink",
        "sink",
        InspectFilters {
            from: Some("entry"),
            to: Some("sink"),
            ..Default::default()
        },
    );
}

#[test]
fn scala_fuzzy_from_across_node_types() {
    let w = ws_multi(
        sc(),
        &[(
            "/w/S.scala",
            "object S {\n  \
                 def process(s: String): Unit = ()\n  \
                 def handleRequest(q: String): Unit = {\n    \
                     val requestUrl = \"/api/request\"\n    \
                     process(requestUrl)\n  \
                 }\n\
             }\n",
        )],
    );
    assert_function_named(&w, "handleRequest");
    assert_function_named(&w, "process");
    assert_fuzzy_substring("handleRequest", "req");
    assert_fuzzy_substring("handleRequest", "REQUEST");
    assert_hit_text_match("/api/request", "req");
    assert_sibling_flow_filter_keeps(&w, "handleRequest", "request", "process");
}

#[test]
fn scala_filter_rejects_unrelated_hits() {
    let w = ws_multi(
        sc(),
        &[("/w/M.scala", "object M { def entry(): Unit = println(\"hi\") }\n")],
    );
    assert_function_named(&w, "entry");
    assert_filter_rejects_unrelated(&w, "entry", "println", "nowhere", "nothere");
}
