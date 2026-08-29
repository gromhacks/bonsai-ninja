//! Focused end-to-end regressions for rule shapes that depend on compiler
//! receiver identity or receiver-state propagation.  These fixtures are
//! deliberately framework-neutral beyond the API named by the rulepack and
//! pair each positive with a same-spelled local collision or safe value.

use std::path::{Path, PathBuf};

fn rules_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("security-patterns")
}

fn sink_ids(path: &str, source: &str) -> Vec<String> {
    let ws = bonsai_workspace::Workspace::new(bonsai_adapters::all_languages_registry());
    ws.vfs().write(path, source);
    let pack = bonsai_security::load_rulepack(&rules_root()).expect("load source-controlled rulepack");
    bonsai_security::run_taint_analysis(
        &ws,
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
fn scala_jdbc_statement_receiver_type_reaches_variable_sql_sink() {
    let ids = sink_ids(
        "Query.scala",
        r#"
import java.sql._
object Query {
  def execute(statement: Statement, input: String): Unit = {
    statement.executeQuery(s"select * from records where id = '$input'")
  }
}
"#,
    );
    assert!(
        ids.iter()
            .any(|id| id == "scala.sqli.jdbc_statement_execute_variable"),
        "typed JDBC receiver did not retain the tainted SQL argument: {ids:#?}"
    );

    let collision = sink_ids(
        "LocalQuery.scala",
        r#"
class Statement { def executeQuery(value: String): Unit = () }
object Query {
  def execute(statement: Statement, input: String): Unit = statement.executeQuery(input)
}
"#,
    );
    assert!(
        collision
            .iter()
            .all(|id| id != "scala.sqli.jdbc_statement_execute_variable"),
        "same-spelled local Statement must not acquire JDBC identity: {collision:#?}"
    );
}

#[test]
fn rust_exhaustive_literal_match_helper_breaks_selector_taint() {
    let safe = sink_ids(
        "SafeQuery.rs",
        r#"
use sqlx::dummy;
fn safe_sort(value: &str) -> &'static str {
    match value {
        "total" => "total",
        "created_at" => "created_at",
        _ => "id",
    }
}

fn execute(input: &str) {
    let sql = format!("select * from records order by {}", safe_sort(input));
    sqlx::query(&sql);
}
"#,
    );
    assert!(
        safe.iter().all(|id| id != "rust.sqli.sqlx_query"),
        "an exhaustive helper whose every match arm returns a literal must remove selector taint: {safe:#?}"
    );

    let unsafe_ids = sink_ids(
        "DynamicQuery.rs",
        r#"
use sqlx::dummy;
fn dynamic_sort(value: &str) -> &str {
    match value {
        "total" => "total",
        _ => value,
    }
}
fn execute(input: &str) {
    let sql = format!("select * from records order by {}", dynamic_sort(input));
    sqlx::query(&sql);
}
"#,
    );
    assert!(
        unsafe_ids.iter().any(|id| id == "rust.sqli.sqlx_query"),
        "a dynamic match arm must preserve selector taint: {unsafe_ids:#?}"
    );
}

#[test]
fn rust_quick_xml_receiver_provenance_honors_only_terminal_doctype_rejection() {
    let safe = sink_ids(
        "SafeXml.rs",
        r#"
use quick_xml::Reader;
struct Bytes;
async fn parse(body: Bytes) {
    let input = String::from_utf8_lossy(&body).to_string();
    if input.contains("<!DOCTYPE") || input.contains("<!ENTITY") { return; }
    let mut reader = Reader::from_str(&input);
    let mut buffer = Vec::new();
    loop {
        match reader.read_event_into(&mut buffer) {
            Ok(_) => break,
            Err(_) => break,
        }
    }
}
"#,
    );
    assert!(
        safe.iter()
            .all(|id| id != "rust.xxe.quick_xml_read_event_into"),
        "a compiler-proven terminal DOCTYPE rejection must cover the reader derived from the guarded input: {safe:#?}"
    );

    let unsafe_ids = sink_ids(
        "ObservedXml.rs",
        r#"
use quick_xml::Reader;
struct Bytes;
async fn parse(body: Bytes) {
    let input = String::from_utf8_lossy(&body).to_string();
    let observed = input.contains("<!DOCTYPE");
    let mut reader = Reader::from_str(&input);
    let mut buffer = Vec::new();
    loop {
        match reader.read_event_into(&mut buffer) {
            Ok(_) => break,
            Err(_) => break,
        }
    }
    consume(observed);
}
"#,
    );
    assert!(
        unsafe_ids
            .iter()
            .any(|id| id == "rust.xxe.quick_xml_read_event_into"),
        "a non-terminal observation must not sanitize the derived reader: {unsafe_ids:#?}"
    );
}

#[test]
fn scala_jdbc_factory_return_types_a_direct_statement_chain() {
    let ids = sink_ids(
        "DirectQuery.scala",
        r#"
import java.sql.Connection
object Query {
  def execute(connection: Connection, input: String): Unit = {
    connection.createStatement().executeQuery("select * from records order by " + input)
  }
}
"#,
    );
    assert!(
        ids.iter()
            .any(|id| id == "scala.sqli.jdbc_statement_execute_variable"),
        "a compiler-typed Connection.createStatement result must type the direct Statement receiver: {ids:#?}"
    );

    let collision = sink_ids(
        "LocalDirectQuery.scala",
        r#"
class LocalStatement { def executeQuery(value: String): Unit = () }
class LocalConnection { def createStatement(): LocalStatement = new LocalStatement }
object Query {
  def execute(connection: LocalConnection, input: String): Unit = {
    connection.createStatement().executeQuery(input)
  }
}
"#,
    );
    assert!(
        collision
            .iter()
            .all(|id| id != "scala.sqli.jdbc_statement_execute_variable"),
        "a same-spelled local factory chain must not acquire JDBC identity: {collision:#?}"
    );
}

#[test]
fn scala_twirl_html_constructor_requires_imported_identity_and_markup_shape() {
    let ids = sink_ids(
        "Page.scala",
        r#"
import play.twirl.api.Html
object Page {
  def render(input: String): Html = new Html("<p>" + input + "</p>")
}
"#,
    );
    assert!(
        ids.iter().any(|id| id == "scala.xss.twirl_html_constructor"),
        "imported Twirl Html constructor did not retain its tainted markup: {ids:#?}"
    );

    let collision = sink_ids(
        "LocalPage.scala",
        r#"
class Html(value: String)
object Page {
  def render(input: String): Html = new Html("<p>" + input + "</p>")
}
"#,
    );
    assert!(
        collision
            .iter()
            .all(|id| id != "scala.xss.twirl_html_constructor"),
        "same-spelled local Html must not acquire Twirl identity: {collision:#?}"
    );
}

#[test]
fn scala_shell_string_is_code_but_sequence_argv_is_data() {
    let shell = sink_ids(
        "Shell.scala",
        r#"
import scala.sys.process._
object Runner {
  def execute(input: String): String = ("sh -c " + input).!!
}
"#,
    );
    assert!(
        shell.iter().any(|id| id == "scala.cmdi.bang_bang"),
        "tainted command-string execution must remain reportable: {shell:#?}"
    );

    let argv = sink_ids(
        "Argv.scala",
        r#"
import scala.sys.process._
object Runner {
  def execute(input: String): String = Seq("/bin/ping", "-c", "1", input).!!
}
"#,
    );
    assert!(
        argv.iter().all(|id| id != "scala.cmdi.bang_bang"),
        "a direct argv sequence must not acquire shell-string semantics: {argv:#?}"
    );
}

#[test]
fn swift_process_run_consumes_tainted_compiler_receiver_state() {
    let ids = sink_ids(
        "Runner.swift",
        r#"
import Foundation
func execute(_ input: String) throws {
    let process = Process()
    process.launchPath = "/bin/sh"
    process.arguments = ["-c", input]
    try process.run()
}
"#,
    );
    assert!(
        ids.iter().any(|id| id == "swift.cmdi.process_run"),
        "Process.run lost tainted receiver state: {ids:#?}"
    );

    let collision = sink_ids(
        "Worker.swift",
        r#"
struct Worker { var command: String; func run() {} }
func execute(_ input: String) { Worker(command: input).run() }
"#,
    );
    assert!(
        collision.iter().all(|id| id != "swift.cmdi.process_run"),
        "unrelated run receiver must not acquire Foundation Process identity: {collision:#?}"
    );

    let direct = sink_ids(
        "DirectRunner.swift",
        r#"
import Foundation
func execute(_ input: String) throws {
    let process = Process()
    process.launchPath = "/usr/bin/printf"
    process.arguments = ["%s", input]
    try process.run()
}
"#,
    );
    assert!(
        direct.iter().all(|id| id != "swift.cmdi.process_run"),
        "direct executable argv must remain data rather than shell syntax: {direct:#?}"
    );
}

#[test]
fn swift_urlsession_static_member_requires_foundation_binding() {
    let ids = sink_ids(
        "Fetch.swift",
        r#"
import Foundation
func fetch(_ input: URL) async throws {
    _ = try await URLSession.shared.data(from: input)
}
"#,
    );
    assert!(
        ids.iter().any(|id| id == "swift.ssrf.urlsession_data_async"),
        "Foundation URLSession.data(from:) did not retain its tainted URL: {ids:#?}"
    );

    let collision = sink_ids(
        "LocalSession.swift",
        r#"
struct URLSession {
    static let shared = URLSession()
    func data(from value: String) {}
}
func fetch(_ input: String) { URLSession.shared.data(from: input) }
"#,
    );
    assert!(
        collision
            .iter()
            .all(|id| id != "swift.ssrf.urlsession_data_async"),
        "same-spelled local URLSession must not acquire Foundation identity: {collision:#?}"
    );
}
