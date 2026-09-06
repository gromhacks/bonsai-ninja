//! End-to-end proof that an adapter-normalized receiver field keeps one exact
//! identity from source storage through a terminal sanitizer guard to a sink.

use bonsai_security::{FindingStatus, Rulepack, TaintAnalysisOptions, TaintAnalysisReport};
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

fn analyze(terminal_rejection: bool) -> TaintAnalysisReport {
    analyze_with_wrapper(terminal_rejection, false)
}

fn analyze_with_wrapper(terminal_rejection: bool, wrapped: bool) -> TaintAnalysisReport {
    let guard_body = if terminal_rejection {
        "throw const FormatException('markup declarations are rejected');"
    } else {
        "print('markup declaration observed');"
    };
    analyze_guard(guard_body, wrapped)
}

fn analyze_guard(guard_body: &str, wrapped: bool) -> TaintAnalysisReport {
    let workspace = Workspace::new(bonsai_adapters::all_languages_registry());
    let predicate = "payload.contains('<!DOCTYPE') || payload.contains('<!ENTITY')";
    let predicate = if wrapped {
        format!("ignore({predicate})")
    } else {
        predicate.to_string()
    };
    workspace.vfs().write(
        "lib/parser.dart",
        Arc::<str>::from(format!(
            r#"import 'package:xml/xml.dart';
class ParserJob {{
  String payload = '';
  String run() {{
    if ({predicate}) {{
      {guard_body}
    }}
    final document = XmlDocument.parse(payload);
    return document.toString();
  }}
}}
bool ignore(bool value) => false;
void abort() {{}}
void sendStatus(int status) {{}}
void exit(int status) {{}}
void panic(String message) {{}}
"#
        )),
    );
    workspace.vfs().write(
        "lib/routes.dart",
        Arc::<str>::from(
            r#"import 'package:shelf/shelf.dart';
import 'parser.dart';
Future<Response> parseHandler(Request request) async {
  final body = await request.readAsString();
  final job = ParserJob()..payload = body;
  return Response.ok(job.run());
}
"#,
        ),
    );
    bonsai_security::run_taint_analysis(
        &workspace,
        rulepack(),
        TaintAnalysisOptions {
            show_sanitized: true,
            ..Default::default()
        },
    )
    .expect("Dart receiver-field guard taint analysis")
}

fn xml_finding(report: &TaintAnalysisReport) -> &bonsai_security::Finding {
    &report
        .findings
        .iter()
        .find(|finding| finding.finding.sink.rule_id == "dart.xxe.xml_document_parse")
        .unwrap_or_else(|| panic!("missing XML parse finding: {:#?}", report.findings))
        .finding
}

#[test]
fn terminal_guard_on_implicit_receiver_field_sanitizes_the_same_sink_place() {
    let report = analyze(true);
    let finding = xml_finding(&report);
    assert_eq!(finding.status, FindingStatus::Sanitized, "{finding:#?}");
    assert!(
        finding
            .sanitizers_seen
            .iter()
            .any(|sanitizer| sanitizer.rule_id == "dart.sanitizer.xml_declaration_rejection"),
        "the exact receiver-field guard must receive sanitizer credit: {finding:#?}"
    );
}

#[test]
fn non_terminal_receiver_field_check_does_not_sanitize_the_sink() {
    let report = analyze(false);
    let finding = xml_finding(&report);
    assert_eq!(finding.status, FindingStatus::Unsanitized, "{finding:#?}");
    assert!(finding.sanitizers_seen.is_empty(), "{finding:#?}");
}

#[test]
fn predicate_inside_a_wrapper_does_not_prove_terminal_rejection() {
    let report = analyze_with_wrapper(true, true);
    let finding = xml_finding(&report);
    assert_eq!(finding.status, FindingStatus::Unsanitized, "{finding:#?}");
    assert!(finding.sanitizers_seen.is_empty(), "{finding:#?}");
}

#[test]
fn returning_calls_with_exit_like_names_do_not_sanitize_the_sink() {
    for call in ["abort();", "sendStatus(400);", "exit(1);", "panic('rejected');"] {
        let report = analyze_guard(call, false);
        let finding = xml_finding(&report);
        assert_eq!(finding.status, FindingStatus::Unsanitized, "{call}: {finding:#?}");
        assert!(finding.sanitizers_seen.is_empty(), "{call}: {finding:#?}");
    }
}
