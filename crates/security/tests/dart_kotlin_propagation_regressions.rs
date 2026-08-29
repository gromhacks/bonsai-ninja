//! End-to-end propagation regressions for Dart receiver state/named arguments
//! and Kotlin expression-bodied `when` dispatch.
//!
//! These tests deliberately use the bundled source and sink rules. They pin
//! the complete compiler -> resolver -> IDG -> security-report path instead of
//! duplicating library/API meaning in engine fixtures.

use bonsai_security::{
    run_sink_analysis, run_source_analysis, run_taint_analysis, Rulepack, SinkAnalysisOptions,
    SourceAnalysisOptions, TaintAnalysisOptions,
};
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
    PACK.get_or_init(|| bonsai_security::load_rulepack(&rules_root()).expect("load bundled rulepack"))
}

fn workspace(files: &[(&str, &str)]) -> Workspace {
    let workspace = Workspace::new(bonsai_adapters::all_languages_registry());
    for (path, source) in files {
        workspace.vfs().write(*path, Arc::<str>::from(*source));
    }
    workspace
}

#[test]
fn dart_cascade_field_store_and_implicit_receiver_read_reach_xxe_sink_analysis() {
    let workspace = workspace(&[
        (
            "lib/routes.dart",
            r#"import 'package:shelf/shelf.dart';
import 'ingest.dart';
Future<Response> feedHandler(Request req) async {
  final body = await req.readAsString();
  final job = FeedJob()..payload = body;
  return Response.ok(job.run());
}
"#,
        ),
        (
            "lib/ingest.dart",
            r#"import 'package:xml/xml.dart';
class FeedJob {
  String payload = '';
  String run() {
    final doc = XmlDocument.parse(payload);
    return doc.toString();
  }
}
"#,
        ),
    ]);

    let findings = run_taint_analysis(&workspace, rulepack(), TaintAnalysisOptions::default())
        .expect("Dart XXE taint analysis");
    let finding = findings
        .findings
        .iter()
        .find(|finding| finding.finding.sink.rule_id == "dart.xxe.xml_document_parse")
        .unwrap_or_else(|| panic!("missing Dart cascade-field XXE finding: {:#?}", findings.findings));
    assert_eq!(finding.finding.source.rule_id, "dart.http.request_read_as_string");
    assert!(
        finding
            .finding
            .sink
            .tainted_args
            .iter()
            .any(|arg| arg.place.as_deref() == Some("this.payload")),
        "the implicit field read must retain the exact receiver field: {finding:#?}"
    );

    let sink_report = run_sink_analysis(
        &workspace,
        rulepack(),
        SinkAnalysisOptions {
            source: Some("^dart\\.http\\.request_read_as_string$".to_string()),
            ..Default::default()
        },
    )
    .expect("Dart XXE sink analysis");
    let endpoint = sink_report
        .candidates
        .iter()
        .find(|candidate| candidate.sink.rule_id == "dart.xxe.xml_document_parse")
        .expect("Dart XXE sink endpoint");
    assert!(
        endpoint.upstream_flows.iter().any(|flow| !flow.endpoint_only),
        "sink-analysis must retain source-independent receiver lineage: {endpoint:#?}"
    );
    assert_eq!(
        endpoint.security_source_flows.len(),
        1,
        "an explicitly requested source proof must agree with taint-analysis: {endpoint:#?}"
    );
}

#[test]
fn dart_named_constructor_arguments_keep_worker_uri_field_identity() {
    let workspace = workspace(&[
        (
            "lib/routes.dart",
            r#"import 'dart:convert';
import 'package:shelf/shelf.dart';
import 'job.dart';
Future<Response> restoreHandler(Request req) async {
  final payload = jsonDecode(await req.readAsString()) as Map<String, dynamic>;
  final job = RestoreJob.fromJson(payload);
  return Response.ok(await runJob(job));
}
"#,
        ),
        (
            "lib/job.dart",
            r#"import 'worker.dart';
class RestoreJob {
  final String workerUri;
  final int retries;
  RestoreJob({required this.workerUri, required this.retries});
  factory RestoreJob.fromJson(Map<String, dynamic> j) => RestoreJob(
    retries: 1,
    workerUri: j['worker'] as String? ?? '',
  );
}
Future<String> runJob(RestoreJob job) => spawnWorker(job.workerUri);
"#,
        ),
        (
            "lib/worker.dart",
            r#"import 'dart:isolate';
Future<String> spawnWorker(String uri) async {
  await Isolate.spawnUri(Uri.parse(uri), const <String>[], null);
  return 'spawned';
}
"#,
        ),
    ]);

    let findings = run_taint_analysis(&workspace, rulepack(), TaintAnalysisOptions::default())
        .expect("Dart named-argument taint analysis");
    let finding = findings
        .findings
        .iter()
        .find(|finding| finding.finding.sink.rule_id == "dart.eval.isolate_spawn_uri")
        .unwrap_or_else(|| panic!("missing Dart worker URI finding: {:#?}", findings.findings));
    assert!(
        finding
            .finding
            .sink
            .tainted_args
            .iter()
            .any(|arg| arg.index == 0 && arg.source_names.iter().any(|name| name == "uri")),
        "the workerUri field must reach spawnWorker's uri parameter: {finding:#?}"
    );

    let source_report = run_source_analysis(
        &workspace,
        rulepack(),
        SourceAnalysisOptions {
            source: Some("^dart\\.http\\.request_read_as_string$".to_string()),
            ..Default::default()
        },
    )
    .expect("Dart named-argument source analysis");
    assert!(
        source_report.candidates.iter().any(|candidate| {
            candidate
                .chain_names
                .windows(2)
                .any(|pair| pair == ["runJob", "spawnWorker"])
        }),
        "source-analysis must retain the workerUri branch as well as other tainted map fields: {:#?}",
        source_report.candidates
    );
}

#[test]
fn dart_named_constructor_does_not_cross_taint_from_retries_into_worker_uri() {
    let workspace = workspace(&[
        (
            "lib/routes.dart",
            r#"import 'dart:convert';
import 'package:shelf/shelf.dart';
import 'job.dart';
Future<Response> restoreHandler(Request req) async {
  final payload = jsonDecode(await req.readAsString()) as Map<String, dynamic>;
  final job = RestoreJob.fromJson(payload);
  return Response.ok(await runJob(job));
}
"#,
        ),
        (
            "lib/job.dart",
            r#"import 'worker.dart';
class RestoreJob {
  final String workerUri;
  final int retries;
  RestoreJob({required this.workerUri, required this.retries});
  factory RestoreJob.fromJson(Map<String, dynamic> j) => RestoreJob(
    retries: j['retries'] as int? ?? 1,
    workerUri: 'file:///safe-worker.dart',
  );
}
Future<String> runJob(RestoreJob job) => spawnWorker(job.workerUri);
"#,
        ),
        (
            "lib/worker.dart",
            r#"import 'dart:isolate';
Future<String> spawnWorker(String uri) async {
  await Isolate.spawnUri(Uri.parse(uri), const <String>[], null);
  return 'spawned';
}
"#,
        ),
    ]);

    let findings = run_taint_analysis(&workspace, rulepack(), TaintAnalysisOptions::default())
        .expect("Dart named-argument negative taint analysis");
    assert!(
        findings
            .findings
            .iter()
            .all(|finding| finding.finding.sink.rule_id != "dart.eval.isolate_spawn_uri"),
        "taint in retries must not cross into the clean workerUri field: {:#?}",
        findings.findings
    );
}

fn kotlin_when_workspace(interpolated: bool) -> Workspace {
    let probe = if interpolated {
        r#"package shop
sealed class Probe {
  data class Ping(val host: String) : Probe()
  object SelfCheck : Probe()
}
object Dispatcher {
  fun handle(p: Probe): String = when (p) {
    is Probe.Ping -> Runner.shell("ping -c 1 ${p.host}")
    Probe.SelfCheck -> Runner.shell("ping -c 1 127.0.0.1")
  }
}
"#
    } else {
        r#"package shop
sealed class Probe {
  data class Ping(val host: String) : Probe()
  object SelfCheck : Probe()
}
object Dispatcher {
  fun handle(p: Probe): String = when (p) {
    is Probe.Ping -> Runner.shell("ping -c 1 ${'$'}{p.host}")
    Probe.SelfCheck -> Runner.shell("ping -c 1 127.0.0.1")
  }
}
"#
    };
    workspace(&[
        (
            "src/main/kotlin/Routes.kt",
            r#"package shop
import io.ktor.server.application.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
fun Route.diagRoutes() {
  get("/ping") {
    val host = call.request.queryParameters["host"] ?: ""
    call.respondText(Dispatcher.handle(Probe.Ping(host)))
  }
}
"#,
        ),
        ("src/main/kotlin/Probe.kt", probe),
        (
            "src/main/kotlin/Runner.kt",
            r#"package shop
object Runner {
  fun shell(cmd: String): String {
    val process = ProcessBuilder("sh", "-c", cmd).start()
    return process.inputStream.bufferedReader().readText()
  }
}
"#,
        ),
    ])
}

#[test]
fn kotlin_expression_body_when_propagates_real_interpolation_but_not_escaped_dollar_text() {
    let dynamic = kotlin_when_workspace(true);
    let graph = dynamic.resolved_call_graph();
    let global = dynamic.db().global_index();
    let handle = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.name == "handle")
        .expect("Kotlin handle declaration");
    let shell = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.name == "shell")
        .expect("Kotlin shell declaration");
    assert!(
        graph
            .callees_of(bonsai_common::FuncId::new(handle.symbol.raw()))
            .any(|edge| edge.to == bonsai_common::FuncId::new(shell.symbol.raw())),
        "the expression-bodied when arm must retain handle -> shell"
    );

    let dynamic_report = run_taint_analysis(&dynamic, rulepack(), TaintAnalysisOptions::default())
        .expect("dynamic Kotlin when taint analysis");
    let finding = dynamic_report
        .findings
        .iter()
        .find(|finding| {
            finding
                .finding
                .sink
                .rule_id
                .starts_with("kotlin.cmdi.processbuilder_")
        })
        .unwrap_or_else(|| {
            panic!(
                "real Kotlin interpolation must reach ProcessBuilder: {:#?}",
                dynamic_report.findings
            )
        });
    let handle_argument = finding
        .finding
        .taint_path
        .iter()
        .find(|step| step.callee == "handle")
        .and_then(|step| step.tainted_args.iter().find(|argument| argument.index == 0))
        .expect("tainted Dispatcher.handle argument");
    assert_eq!(
        handle_argument.value_text, "Probe.Ping(host)",
        "lineage rendering must use the compiler-emitted argument, not the static receiver"
    );

    let literal = kotlin_when_workspace(false);
    let literal_report = run_taint_analysis(&literal, rulepack(), TaintAnalysisOptions::default())
        .expect("escaped-dollar Kotlin when taint analysis");
    assert!(
        literal_report.findings.iter().all(|finding| {
            !finding
                .finding
                .sink
                .rule_id
                .starts_with("kotlin.cmdi.processbuilder_")
        }),
        "escaped dollar text is a literal and must not fabricate a taint operand: {:#?}",
        literal_report.findings
    );
}
