//! Compiler-to-IDG source-boundary tests for Rust and Scala.
//!
//! These are deliberately end-to-end: exact Tree-sitter facts must select
//! the rule, collision shapes must stay clean, and the selected carrier must
//! reach a real sink through the production IDG closure.

use std::path::{Path, PathBuf};

fn rules_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("security-patterns")
}

fn workspace(path: &str, source: &str) -> bonsai_workspace::Workspace {
    let ws = bonsai_workspace::Workspace::new(bonsai_adapters::all_languages_registry());
    ws.vfs().write(path, source);
    ws
}

fn source_ids(ws: &bonsai_workspace::Workspace) -> Vec<String> {
    let pack = bonsai_security::load_rulepack(&rules_root()).expect("load rulepack");
    bonsai_security::source_inventory(ws, &pack, Default::default())
        .expect("source inventory")
        .into_iter()
        .map(|source| source.rule_id)
        .collect()
}

#[test]
fn rust_typed_broker_fields_match_and_reach_command_sink() {
    for (source, expected_rule) in [
        (
            r#"
use lapin::message::Delivery;
fn consume(delivery: Delivery) {
    std::process::Command::new(delivery.data);
}
"#,
            "rust.lapin.delivery_data",
        ),
        (
            r#"
use async_nats::Message;
fn consume(message: Message) {
    std::process::Command::new(message.payload);
}
"#,
            "rust.nats.message_data",
        ),
    ] {
        let ws = workspace("consumer.rs", source);
        let ids = source_ids(&ws);
        assert!(
            ids.iter().any(|id| id == expected_rule),
            "missing {expected_rule}: {ids:#?}"
        );
        let pack = bonsai_security::load_rulepack(&rules_root()).expect("load rulepack");
        let report =
            bonsai_security::run_taint_analysis(&ws, &pack, Default::default()).expect("Rust taint analysis");
        assert!(
            report.findings.iter().any(|finding| {
                finding.finding.source.rule_id == expected_rule
                    && finding.finding.sink.rule_id == "rust.cmdi.std_command_new_shell"
            }),
            "{expected_rule} did not reach the command sink: {:#?}",
            report.findings
        );
    }
}

#[test]
fn rust_shell_wrapper_sink_requires_execution_and_exact_imported_builder_identity() {
    let analyze = |source: &str| {
        let ws = workspace("routes.rs", source);
        let pack = bonsai_security::load_rulepack(&rules_root()).expect("load rulepack");
        bonsai_security::run_taint_analysis(&ws, &pack, Default::default())
            .expect("Rust shell-wrapper taint analysis")
    };

    let vulnerable = analyze(
        r#"
use axum::extract::Query;
use std::process::Command;
fn execute(Query(input): Query<String>) {
    let _ = Command::new("sh").arg("-c").arg(&input).output();
}
"#,
    );
    assert!(
        vulnerable.findings.iter().any(|finding| {
            finding.finding.source.rule_id == "rust.axum.query"
                && finding.finding.sink.rule_id == "rust.cmdi.std_command_shell_wrapper_output"
        }),
        "the exact imported and executed shell wrapper must retain its source-to-sink flow: {:#?}",
        vulnerable.findings
    );

    let direct_argv = analyze(
        r#"
use axum::extract::Query;
use std::process::Command;
fn execute(Query(input): Query<String>) {
    let _ = Command::new("ping").arg("-c").arg(&input).output();
}
"#,
    );
    assert!(
        direct_argv
            .findings
            .iter()
            .all(|finding| finding.finding.sink.rule_id != "rust.cmdi.std_command_shell_wrapper_output"),
        "a dynamic argv element without a shell interpreter must remain outside the shell-wrapper sink: {:#?}",
        direct_argv.findings
    );

    let unexecuted = analyze(
        r#"
use axum::extract::Query;
use std::process::Command;
fn configure(Query(input): Query<String>) {
    let _ = Command::new("sh").arg("-c").arg(&input);
}
"#,
    );
    assert!(
        unexecuted
            .findings
            .iter()
            .all(|finding| finding.finding.sink.rule_id != "rust.cmdi.std_command_shell_wrapper_output"),
        "an unexecuted builder is not a process-execution sink: {:#?}",
        unexecuted.findings
    );

    let shadowed = analyze(
        r#"
use axum::extract::Query;
use std::process::Command as StdCommand;
struct Command;
impl Command {
    fn new(_: &str) -> Self { Self }
    fn arg(self, _: &str) -> Self { self }
    fn output(self) {}
}
fn execute(Query(input): Query<String>) {
    Command::new("sh").arg("-c").arg(&input).output();
}
"#,
    );
    assert!(
        shadowed
            .findings
            .iter()
            .all(|finding| finding.finding.sink.rule_id != "rust.cmdi.std_command_shell_wrapper_output"),
        "a same-spelled local builder must not inherit std::process::Command identity: {:#?}",
        shadowed.findings
    );
}

#[test]
fn rust_same_named_fields_on_local_types_are_not_broker_sources() {
    let ws = workspace(
        "consumer.rs",
        r#"
use lapin::message::Delivery;
use async_nats::Message;
struct Local { data: Vec<u8>, payload: Vec<u8> }
fn consume(local: Local) {
    std::process::Command::new(local.data);
    std::process::Command::new(local.payload);
}
"#,
    );
    let ids = source_ids(&ws);
    for unexpected in ["rust.lapin.delivery_data", "rust.nats.message_data"] {
        assert!(
            ids.iter().all(|id| id != unexpected),
            "collision produced {unexpected}: {ids:#?}"
        );
    }
}

#[test]
fn rust_warp_filter_callbacks_are_sources_but_descriptors_and_local_methods_are_not() {
    for (shape, source) in [
        (
            "inline",
            r#"
use std::collections::HashMap;
use warp::Filter;
fn route() {
    warp::path("run")
        .and(warp::query::<HashMap<String, String>>())
        .and_then(|query| async move { std::process::Command::new(query) });
}
"#,
        ),
        (
            "assigned",
            r#"
use std::collections::HashMap;
use warp::Filter;
fn route() {
    let input = warp::query::<HashMap<String, String>>();
    input.and_then(|query| async move { std::process::Command::new(query) });
}
"#,
        ),
        (
            "assigned composition",
            r#"
use std::collections::HashMap;
use warp::Filter;
fn route() {
    let input = warp::query::<HashMap<String, String>>();
    let combined = input.and(warp::body::bytes());
    combined.and_then(|query, body| async move {
        std::process::Command::new(query);
        std::process::Command::new(body);
    });
}
"#,
        ),
    ] {
        let ws = workspace("routes.rs", source);
        if shape == "assigned composition" {
            let file = ws.vfs().all_files()[0];
            let index = ws.db().decl_index(file).expect("Rust compiler index");
            let syntax = bonsai_lang_api::CompilerSyntaxHeader::from_decl_index(&index);
            let input = syntax
                .factory_assignments
                .iter()
                .find(|assignment| assignment.target == "input")
                .unwrap_or_else(|| panic!("missing exact factory assignment for input: {syntax:#?}"));
            assert_eq!(input.call_name, "warp::query");
            assert_eq!(input.call_receiver.as_deref(), Some("warp"));
            let combined = syntax
                .factory_assignments
                .iter()
                .find(|assignment| assignment.target == "combined")
                .unwrap_or_else(|| panic!("missing exact factory assignment for combined: {syntax:#?}"));
            assert_eq!(combined.call_name, "input.and");
            assert_eq!(combined.call_receiver.as_deref(), Some("input"));
            let terminal = syntax
                .calls
                .iter()
                .find(|call| call.name.ends_with("and_then") && call.receiver.as_deref() == Some("combined"))
                .unwrap_or_else(|| panic!("missing terminal and_then call: {syntax:#?}"));
            assert_eq!(terminal.name, "combined.and_then");
            assert_eq!(terminal.receiver.as_deref(), Some("combined"));
        }
        let ids = source_ids(&ws);
        let expected_rule = if shape == "inline" {
            "rust.warp.filter_callback_inline"
        } else {
            "rust.warp.filter_callback_typed"
        };
        assert!(
            ids.iter().any(|id| id == expected_rule),
            "Warp {shape} callback source rule {expected_rule} did not match: {ids:#?}"
        );
        let pack = bonsai_security::load_rulepack(&rules_root()).expect("load rulepack");
        let report =
            bonsai_security::run_taint_analysis(&ws, &pack, Default::default()).expect("Warp taint analysis");
        assert!(
            report.findings.iter().any(|finding| {
                finding
                    .finding
                    .source
                    .rule_id
                    .starts_with("rust.warp.filter_callback_")
                    && finding.finding.sink.rule_id == "rust.cmdi.std_command_new_shell"
            }),
            "Warp {shape} callback source did not reach sink: {:#?}",
            report.findings
        );
    }

    let ws = workspace(
        "routes.rs",
        r#"
use warp::Filter;
struct Local;
impl Local { fn and_then<F>(&self, callback: F) {} }
fn route(local: Local) {
    let descriptor = warp::query::<String>();
    local.and_then(|value| std::process::Command::new(value));
}
"#,
    );
    let ids = source_ids(&ws);
    assert!(
        ids.iter().all(|id| !id.starts_with("rust.warp.filter_callback_")),
        "descriptor or local method became a Warp source: {ids:#?}"
    );
}

#[test]
fn scala_akka_curried_directives_source_every_callback_parameter() {
    let ws = workspace(
        "Routes.scala",
        r#"
import akka.http.scaladsl.server.Directives._
object Routes {
  def route = parameters("cmd", "fallback") { (cmd, fallback) =>
    Runtime.getRuntime.exec(cmd)
    Runtime.getRuntime.exec(fallback)
  }
}
"#,
    );
    let ids = source_ids(&ws);
    assert!(
        ids.iter().any(|id| id == "scala.akka.parameters"),
        "missing compiler-owned Akka callback source: {ids:#?}"
    );
    let pack = bonsai_security::load_rulepack(&rules_root()).expect("load rulepack");
    let report =
        bonsai_security::run_taint_analysis(&ws, &pack, Default::default()).expect("Scala taint analysis");
    let findings = report
        .findings
        .iter()
        .filter(|finding| {
            finding.finding.source.rule_id == "scala.akka.parameters"
                && finding.finding.sink.rule_id == "scala.cmdi.runtime_exec"
        })
        .count();
    assert_eq!(
        findings, 2,
        "both exact callback parameters must reach their sinks: {:#?}",
        report.findings
    );
}

#[test]
fn scala_directive_constructor_and_same_named_method_stay_clean() {
    let ws = workspace(
        "Routes.scala",
        r#"
import akka.http.scaladsl.server.Directives._
object Routes {
  val descriptor = parameters("q")
  def local(builder: Builder) = builder.parameters("q") { q => Runtime.getRuntime.exec(q) }
}
class Builder { def parameters(name: String)(f: String => Unit): Unit = f(name) }
"#,
    );
    let ids = source_ids(&ws);
    assert!(
        ids.iter().all(|id| id != "scala.akka.parameters"),
        "constructor result or receiver method became a source: {ids:#?}"
    );
}

#[test]
fn scala_http4s_tapir_and_zio_callbacks_bind_remote_values() {
    for (source, expected) in [
        (
            r#"
import org.http4s._
import org.http4s.dsl.io._
object App {
  val routes = HttpRoutes.of[IO] {
    case request @ GET -> Root / "run" => Runtime.getRuntime.exec(request.uri.path.renderString)
  }
}
"#,
            "scala.http4s.request_body",
        ),
        (
            r#"
import sttp.tapir._
object App {
  val route = endpoint.in(query[String]("cmd")).serverLogic {
    cmd => scala.concurrent.Future.successful(Right(Runtime.getRuntime.exec(cmd)))
  }
}
"#,
            "scala.tapir.input_query",
        ),
        (
            r#"
import zio.http._
object App {
  val route = Routes(Method.POST / "run" -> handler {
    (request: Request) => Runtime.getRuntime.exec(request.url.path.encode)
  })
}
"#,
            "scala.zio.http_request_body",
        ),
    ] {
        let ws = workspace("Routes.scala", source);
        let ids = source_ids(&ws);
        assert!(
            ids.iter().any(|id| id == expected),
            "missing {expected}: {ids:#?}"
        );
        let pack = bonsai_security::load_rulepack(&rules_root()).expect("load rulepack");
        let report = bonsai_security::run_taint_analysis(&ws, &pack, Default::default())
            .expect("Scala framework taint analysis");
        assert!(
            report.findings.iter().any(|finding| {
                finding.finding.source.rule_id == expected
                    && finding.finding.sink.rule_id == "scala.cmdi.runtime_exec"
            }),
            "{expected} did not reach the sink: {:#?}",
            report.findings
        );
    }
}
