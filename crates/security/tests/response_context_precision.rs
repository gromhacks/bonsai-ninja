use std::path::{Path, PathBuf};

fn rules_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("security-patterns")
}

fn sink_ids(path: &str, source: &str) -> Vec<String> {
    let workspace = bonsai_workspace::Workspace::new(bonsai_adapters::all_languages_registry());
    workspace.vfs().write(path, source);
    let pack = bonsai_security::load_rulepack(&rules_root()).expect("load rulepack");
    bonsai_security::run_taint_analysis(
        &workspace,
        &pack,
        bonsai_security::TaintAnalysisOptions {
            include_inferred_sources: true,
            ..Default::default()
        },
    )
    .expect("taint analysis")
    .findings
    .into_iter()
    .map(|finding| finding.finding.sink.rule_id)
    .collect()
}

#[test]
fn raw_response_writes_are_not_html_sinks_without_execution_context() {
    let c = sink_ids(
        "response.c",
        r#"#include <civetweb.h>
int emit(struct mg_connection *connection, const char *body, unsigned long size) {
  return mg_write(connection, body, size);
}
"#,
    );
    assert!(
        c.iter().all(|id| id != "c.xss.civetweb_write_body"),
        "a byte response without HTML context must stay out of XSS: {c:#?}"
    );

    let cpp = sink_ids(
        "response.cpp",
        r#"#include <crow.h>
crow::response emit(const std::string& body) {
  return crow::response(body);
}
"#,
    );
    assert!(
        cpp.iter().all(|id| id != "cpp.xss.crow_response_constructor"),
        "a raw Crow body has no proven HTML execution context: {cpp:#?}"
    );

    let lua = sink_ids(
        "response.lua",
        r#"local function emit(body)
  ngx.say(render(body))
end
"#,
    );
    assert!(
        lua.iter().all(|id| id != "lua.xss.ngx_say"),
        "a raw OpenResty body has no proven HTML execution context: {lua:#?}"
    );
}

#[test]
fn explicit_inline_html_contexts_remain_xss_sinks() {
    let cpp = sink_ids(
        "response.cpp",
        r#"#include <crow.h>
crow::response emit(const std::string& value) {
  return crow::response("<p>" + value + "</p>");
}
"#,
    );
    assert!(
        cpp.iter().any(|id| id == "cpp.xss.crow_response_constructor"),
        "explicit dynamic Crow HTML must remain an XSS boundary: {cpp:#?}"
    );

    let lua = sink_ids(
        "response.lua",
        r#"local function emit(value)
  ngx.say("<p>" .. value .. "</p>")
end
"#,
    );
    assert!(
        lua.iter().any(|id| id == "lua.xss.ngx_say"),
        "explicit dynamic OpenResty HTML must remain an XSS boundary: {lua:#?}"
    );
}
