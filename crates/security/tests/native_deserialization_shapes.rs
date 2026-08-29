use bonsai_security::{Rulepack, TaintAnalysisOptions, TaintAnalysisReport};
use bonsai_workspace::Workspace;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};

fn rules_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("security-patterns")
}

fn rulepack() -> &'static Rulepack {
    static PACK: OnceLock<Rulepack> = OnceLock::new();
    PACK.get_or_init(|| bonsai_security::load_rulepack(&rules_root()).expect("load rulepack"))
}

fn analyze(files: &[(&str, &str)]) -> TaintAnalysisReport {
    let workspace = Workspace::new(bonsai_adapters::all_languages_registry());
    for (path, source) in files {
        workspace
            .vfs()
            .write(*path, Arc::<str>::from((*source).to_string()));
    }
    bonsai_security::run_taint_analysis(
        &workspace,
        rulepack(),
        TaintAnalysisOptions {
            include_inferred_sources: true,
            show_sanitized: true,
            ..Default::default()
        },
    )
    .expect("taint analysis")
}

fn sink_rules(report: &TaintAnalysisReport) -> Vec<&str> {
    report
        .findings
        .iter()
        .map(|finding| finding.finding.sink.rule_id.as_str())
        .collect()
}

#[test]
fn c_raw_bytes_into_complete_record_is_distinct_from_bounded_byte_copy() {
    let unsafe_report = analyze(&[
        (
            "server.c",
            r#"#include <sys/socket.h>
void restore_session(const unsigned char *, unsigned);
void handle(int fd) {
  unsigned char wire[256];
  int n = recv(fd, wire, sizeof(wire), 0);
  if (n > 0) restore_session(wire, (unsigned)n);
}
"#,
        ),
        (
            "session.c",
            r#"#include <string.h>
typedef struct { unsigned role; char name[32]; } session_t;
void restore_session(const unsigned char *wire, unsigned n) {
  session_t state;
  memcpy(&state, wire, n < sizeof(state) ? n : sizeof(state));
}
"#,
        ),
    ]);
    assert!(
        sink_rules(&unsafe_report).contains(&"c.deser.memcpy_into_aggregate"),
        "cross-file remote bytes must reach native-record reconstruction: {:#?}",
        unsafe_report.findings
    );

    let bounded_byte_copy = analyze(&[(
        "buffer.c",
        r#"#include <string.h>
void restore(const unsigned char *input, unsigned n) {
  unsigned char bytes[64];
  if (n > sizeof(bytes)) n = sizeof(bytes);
  memcpy(bytes, input, n);
}
"#,
    )]);
    assert!(
        !sink_rules(&bounded_byte_copy).contains(&"c.deser.memcpy_into_aggregate"),
        "bounded byte-buffer copy is not object reconstruction: {:#?}",
        bounded_byte_copy.findings
    );

    let trusted_record = analyze(&[(
        "trusted.c",
        r#"#include <string.h>
typedef struct { unsigned role; } session_t;
void restore(void) {
  static const unsigned char trusted[] = {0, 0, 0, 0};
  session_t state;
  memcpy(&state, trusted, sizeof(state));
}
"#,
    )]);
    assert!(
        !sink_rules(&trusted_record).contains(&"c.deser.memcpy_into_aggregate"),
        "literal static bytes have no untrusted source: {:#?}",
        trusted_record.findings
    );
}

#[test]
fn lua_serialized_expression_has_one_specialized_finding_across_module_boundary() {
    let report = analyze(&[
        (
            "codec.lua",
            r#"local M = {}
function M.restore(blob)
  local chunk = load("return " .. blob)
  return chunk()
end
return M
"#,
        ),
        (
            "handler.lua",
            r#"local codec = require("codec")
function handle()
  local body = ngx.req.get_body_data()
  return codec.restore(body)
end
"#,
        ),
    ]);
    let specialized = report
        .findings
        .iter()
        .filter(|finding| finding.finding.sink.rule_id == "lua.deser.load_return_expression")
        .count();
    assert_eq!(specialized, 1, "{:#?}", report.findings);
    assert!(
        !sink_rules(&report).contains(&"lua.eval.load"),
        "the specialized expression must not be duplicated as generic eval: {:#?}",
        report.findings
    );

    let ordinary_eval = analyze(&[(
        "eval.lua",
        r#"function execute(input)
  return load(input)
end
"#,
    )]);
    assert!(sink_rules(&ordinary_eval).contains(&"lua.eval.load"));
    assert!(!sink_rules(&ordinary_eval).contains(&"lua.deser.load_return_expression"));

    let literal = analyze(&[(
        "literal.lua",
        r#"function restore()
  return load("return { role = 'reader' }")
end
"#,
    )]);
    assert!(!sink_rules(&literal).contains(&"lua.eval.load"));
    assert!(!sink_rules(&literal).contains(&"lua.deser.load_return_expression"));
}
