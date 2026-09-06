//! Persisted source-to-sink regressions for JVM and Swift security boundaries.
//! Each unsafe flow has a literal, guarded, or non-interpreting counterpart.

use bonsai_security::{FindingStatus, TaintAnalysisOptions, TaintAnalysisReport};
use std::path::{Path, PathBuf};

fn rules_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("security-patterns")
}

fn persisted_report(files: &[(&str, &str)]) -> TaintAnalysisReport {
    let root = tempfile::tempdir_in(env!("CARGO_MANIFEST_DIR"))
        .expect("temporary persisted workspace inside the writable checkout");
    for (relative, source) in files {
        let path = root.path().join(relative);
        std::fs::create_dir_all(path.parent().expect("fixture parent")).expect("create fixture directory");
        std::fs::write(path, source).expect("write fixture source");
    }
    let registry = bonsai_adapters::all_languages_registry();
    let workspace =
        bonsai_workspace::Workspace::index(root.path(), registry).expect("index persisted workspace");
    let pack = bonsai_security::load_rulepack(&rules_root()).expect("load source-controlled rulepack");
    bonsai_security::run_taint_analysis(
        &workspace,
        &pack,
        TaintAnalysisOptions {
            include_inferred_sources: true,
            show_sanitized: true,
            ..Default::default()
        },
    )
    .expect("run persisted taint analysis")
}

fn has_unsanitized(report: &TaintAnalysisReport, sink_rule: &str, function: &str) -> bool {
    report.findings.iter().any(|finding| {
        finding.finding.sink.rule_id == sink_rule
            && finding.finding.sink.enclosing_fn.as_deref() == Some(function)
            && finding.finding.status == FindingStatus::Unsanitized
    })
}

#[test]
fn java_async_request_body_reaches_jexl_through_helper() {
    let report = persisted_report(&[(
        "src/main/java/app/Routes.java",
        r#"
package app;
import io.vertx.core.http.HttpServerRequest;
import org.apache.commons.jexl3.JexlEngine;

class Routes {
    void register(HttpServerRequest request, JexlEngine engine) {
        request.bodyHandler(buffer -> evaluateDynamic(engine, buffer.toString()));
        request.bodyHandler(buffer -> evaluateLiteral(engine));
    }
    void evaluateDynamic(JexlEngine engine, String script) {
        engine.createScript(script);
    }
    void evaluateLiteral(JexlEngine engine) {
        engine.createScript("1 + 1");
    }
}
"#,
    )]);
    assert!(
        has_unsanitized(&report, "java.eval.jexl_createscript", "evaluateDynamic"),
        "async request bytes must reach the helper sink: {:#?}",
        report.findings
    );
    assert!(
        !has_unsanitized(&report, "java.eval.jexl_createscript", "evaluateLiteral"),
        "a literal expression must remain clean: {:#?}",
        report.findings
    );
}

#[test]
fn java_normalized_path_containment_credits_only_the_rejecting_branch() {
    let report = persisted_report(&[(
        "src/main/java/app/AssetReader.java",
        r#"
package app;
import java.nio.file.Files;
import java.nio.file.Path;

class AssetReader {
    private static final Path BASE = Path.of("/var/data/assets");

    byte[] safe(String name) throws Exception {
        Path base = BASE.toAbsolutePath().normalize();
        Path target = base.resolve(name).normalize();
        if (!target.startsWith(base)) throw new Exception("outside");
        return Files.readAllBytes(target);
    }

    byte[] wrongDirection(String name) throws Exception {
        Path base = BASE.toAbsolutePath().normalize();
        Path target = base.resolve(name).normalize();
        if (target.startsWith(base)) throw new Exception("inside");
        return Files.readAllBytes(target);
    }
}
"#,
    )]);

    let finding = |function: &str| {
        report.findings.iter().find(|finding| {
            finding.finding.sink.rule_id == "java.path.files_read_all_bytes"
                && finding.finding.sink.enclosing_fn.as_deref() == Some(function)
        })
    };
    assert_eq!(
        finding("safe").map(|finding| finding.finding.status),
        Some(FindingStatus::Sanitized),
        "a normalized absolute static base plus a rejecting containment branch must receive credit: {:#?}",
        report.findings,
    );
    assert_eq!(
        finding("wrongDirection").map(|finding| finding.finding.status),
        Some(FindingStatus::Unsanitized),
        "the opposite branch direction must remain reportable: {:#?}",
        report.findings,
    );
}

#[test]
fn java_guard_helpers_must_reject_in_their_own_control_flow() {
    let report = persisted_report(&[(
        "src/main/java/app/Redirects.java",
        r#"
package app;
import jakarta.servlet.http.HttpServletResponse;
class Redirects {
    static String safe(String target) {
        if (!target.startsWith("/") || target.startsWith("//")) { return "/"; }
        return target;
    }
    static String conditional(String target) {
        if (!target.startsWith("/") || target.startsWith("//")) { if (target.isEmpty()) return "/"; }
        return target;
    }
    static String callback(String target) {
        if (!target.startsWith("/") || target.startsWith("//")) {
            java.util.function.Supplier<String> unused = () -> { return "/"; };
        }
        return target;
    }
    void safeRedirect(String next, HttpServletResponse response) throws Exception {
        response.sendRedirect(safe(next));
    }
    void conditionalRedirect(String next, HttpServletResponse response) throws Exception {
        response.sendRedirect(conditional(next));
    }
    void callbackRedirect(String next, HttpServletResponse response) throws Exception {
        response.sendRedirect(callback(next));
    }
}
"#,
    )]);
    let status = |function: &str| {
        report
            .findings
            .iter()
            .find(|finding| {
                finding.finding.sink.rule_id == "java.open_redirect.send_redirect"
                    && finding.finding.sink.enclosing_fn.as_deref() == Some(function)
            })
            .map(|finding| finding.finding.status)
    };
    assert_eq!(
        status("safeRedirect"),
        Some(FindingStatus::Sanitized),
        "{:#?}",
        report.findings
    );
    for function in ["conditionalRedirect", "callbackRedirect"] {
        assert_eq!(
            status(function),
            Some(FindingStatus::Unsanitized),
            "{function}: {:#?}",
            report.findings
        );
    }
}

#[test]
fn kotlin_route_value_wrappers_reach_shell_but_direct_argv_stays_data() {
    let report = persisted_report(&[(
        "src/main/kotlin/app/Routes.kt",
        r#"
package app
import io.ktor.server.application.*
import io.ktor.server.routing.*

data class RequestData(val command: String)
sealed class Action {
    data class Shell(val command: String) : Action()
}
class Service {
    fun executeShell(action: Action.Shell) {
        ProcessBuilder("sh", "-c", action.command)
    }
    fun executeDirect(action: Action.Shell) {
        ProcessBuilder("/usr/bin/printf", "%s", action.command)
    }
    fun executeList(action: Action.Shell) {
        val argv = listOf("/usr/bin/printf", "%s", action.command)
        ProcessBuilder(argv).start()
    }
    fun executeDynamic(action: Action.Shell) {
        val argv = listOf(action.command, "--version")
        ProcessBuilder(argv).start()
    }
    fun executeViaSafeHelper(action: Action.Shell) {
        acceptSafe(listOf("/usr/bin/printf", "%s", action.command))
    }
    fun executeViaDynamicHelper(action: Action.Shell) {
        acceptDynamic(listOf(action.command, "--version"))
    }
    private fun acceptSafe(argv: List<String>) {
        ProcessBuilder(argv).start()
    }
    private fun acceptDynamic(argv: List<String>) {
        ProcessBuilder(argv).start()
    }
}
fun Route.routes(service: Service) {
    get("/run") {
        val command = call.request.queryParameters["command"] ?: ""
        val request = RequestData(command)
        val action = Action.Shell(request.command)
        service.executeShell(action)
        service.executeDirect(action)
        service.executeList(action)
        service.executeDynamic(action)
        service.executeViaSafeHelper(action)
        service.executeViaDynamicHelper(action)
    }
}
"#,
    )]);
    assert!(
        has_unsanitized(
            &report,
            "kotlin.cmdi.processbuilder_shell_command",
            "executeShell"
        ),
        "route query data must cross data/sealed wrappers into the shell token: {:#?}",
        report.findings
    );
    assert!(
        !has_unsanitized(
            &report,
            "kotlin.cmdi.processbuilder_shell_command",
            "executeDirect"
        ),
        "direct executable argv must not acquire shell semantics: {:#?}",
        report.findings
    );
    assert!(
        report.findings.iter().all(|finding| {
            !matches!(
                finding.finding.sink.enclosing_fn.as_deref(),
                Some("executeDirect" | "executeList")
            ) || finding.finding.tag.as_deref() != Some("command-injection")
                || finding.finding.status != FindingStatus::Unsanitized
        }),
        "a static executable plus tainted argv data is not command injection: {:#?}",
        report.findings
    );
    assert!(
        has_unsanitized(&report, "kotlin.cmdi.processbuilder_ctor", "executeDynamic"),
        "a tainted executable in argv position zero must remain command injection: {:#?}",
        report.findings
    );
    assert!(
        !has_unsanitized(&report, "kotlin.cmdi.processbuilder_ctor", "acceptSafe"),
        "an exact static executable must remain data across a helper boundary: {:#?}",
        report.findings
    );
    assert!(
        has_unsanitized(&report, "kotlin.cmdi.processbuilder_ctor", "acceptDynamic"),
        "a dynamic executable must remain reportable across the same helper boundary: {:#?}",
        report.findings
    );
}

#[test]
fn kotlin_path_and_url_guards_credit_only_complete_proofs() {
    let report = persisted_report(&[(
        "src/main/kotlin/app/GuardedConsumers.kt",
        r#"
package app
import java.net.URI
import java.nio.file.Files
import java.nio.file.Path
import play.libs.ws.WSClient

fun safePath(name: String): ByteArray {
    val root = Path.of("/srv/data")
    val base = root.toRealPath()
    val target = base.resolve(name).toRealPath()
    if (!target.startsWith(base)) { throw IllegalArgumentException() }
    return Files.readAllBytes(target)
}
fun unsafePath(name: String): ByteArray {
    return Files.readAllBytes(Path.of("/srv/data").resolve(name))
}
class UrlService(private val client: WSClient) {
    fun safeUrl(raw: String) {
        val parsed = URI.create(raw)
        if (parsed.scheme != "https") { throw IllegalArgumentException() }
        val allowed = setOf("api.example.test", "media.example.test")
        if (!allowed.contains(parsed.host)) { throw IllegalArgumentException() }
        val rebuilt = "https://${parsed.host}${parsed.path ?: "/"}"
        client.url(rebuilt)
    }
    fun unsafeUrl(raw: String) {
        client.url(raw)
    }
    fun missingHostUrl(raw: String) {
        val parsed = URI.create(raw)
        if (parsed.scheme != "https") { throw IllegalArgumentException() }
        val rebuilt = "https://${parsed.host}${parsed.path ?: "/"}"
        client.url(rebuilt)
    }
}
"#,
    )]);

    let finding = |rule: &str, function: &str| {
        report.findings.iter().find(|finding| {
            finding.finding.sink.rule_id == rule
                && finding.finding.sink.enclosing_fn.as_deref() == Some(function)
        })
    };
    if let Some(safe) = finding("kotlin.path.files_read_all_bytes", "safePath") {
        assert_eq!(
            safe.finding.status,
            FindingStatus::Sanitized,
            "a retained canonical-containment lineage must receive sanitizer credit: {:#?}",
            report.findings
        );
    }
    assert!(
        has_unsanitized(&report, "kotlin.path.files_read_all_bytes", "unsafePath"),
        "unguarded path must remain reportable: {:#?}",
        report.findings
    );
    assert_eq!(
        finding("kotlin.ssrf.play_wsclient_url", "safeUrl").map(|f| f.finding.status),
        Some(FindingStatus::Sanitized),
        "scheme plus finite host membership must receive URL reconstruction credit: {:#?}",
        report.findings
    );
    assert!(
        has_unsanitized(&report, "kotlin.ssrf.play_wsclient_url", "unsafeUrl"),
        "an unguarded URL must remain reportable: {:#?}",
        report.findings
    );
    assert_eq!(
        finding("kotlin.ssrf.play_wsclient_url", "missingHostUrl").map(|finding| finding.finding.status),
        Some(FindingStatus::WrongContext),
        "scheme validation without a finite host proof must be denied guard credit: {:#?}",
        report.findings,
    );
}

#[test]
fn scala_guarded_match_url_allowlist_requires_scheme_host_and_redirect_proofs() {
    let report = persisted_report(&[(
        "app/FetchService.scala",
        r#"
package app
import java.net.URI
import scala.util.Try
import play.api.libs.ws._

class FetchService(ws: WSClient) {
  private val allowed = Set("api.example.test", "media.example.test")

  def safe(raw: String): Unit = {
    val parsed = Try(new URI(raw)).toOption
    parsed match {
      case Some(uri) if uri.getScheme == "https" && allowed.contains(uri.getHost) =>
        ws.url(raw).withFollowRedirects(false).get()
      case _ => ()
    }
  }

  def missingHost(raw: String): Unit = {
    val parsed = Try(new URI(raw)).toOption
    parsed match {
      case Some(uri) if uri.getScheme == "https" =>
        ws.url(raw).withFollowRedirects(false).get()
      case _ => ()
    }
  }

  def dynamicHosts(raw: String, host: String): Unit = {
    val hosts = Set(host)
    val parsed = Try(new URI(raw)).toOption
    parsed match {
      case Some(uri) if uri.getScheme == "https" && hosts.contains(uri.getHost) =>
        ws.url(raw).withFollowRedirects(false).get()
      case _ => ()
    }
  }

  def redirectsEnabled(raw: String): Unit = {
    val parsed = Try(new URI(raw)).toOption
    parsed match {
      case Some(uri) if uri.getScheme == "https" && allowed.contains(uri.getHost) =>
        ws.url(raw).withFollowRedirects(true).get()
      case _ => ()
    }
  }
}
"#,
    )]);

    let finding = |function: &str| {
        report.findings.iter().find(|finding| {
            finding.finding.sink.rule_id == "scala.ssrf.play_ws_url"
                && finding.finding.sink.enclosing_fn.as_deref() == Some(function)
        })
    };
    assert_eq!(
        finding("safe").map(|finding| finding.finding.status),
        Some(FindingStatus::Sanitized),
        "the complete compiler-proven guarded match must receive credit: {:#?}",
        report.findings
    );
    for function in ["missingHost", "dynamicHosts", "redirectsEnabled"] {
        assert_eq!(
            finding(function).map(|finding| finding.finding.status),
            Some(FindingStatus::Unsanitized),
            "an incomplete or dynamic URL proof must remain reportable for {function}: {:#?}",
            report.findings
        );
    }
}

#[test]
fn swift_request_wrappers_and_raw_html_reach_their_service_boundaries() {
    let report = persisted_report(&[(
        "Sources/App/Routes.swift",
        r#"
import Vapor

enum CommandEvent { case command(String); case none }
struct Service {
    func execute(_ event: CommandEvent) {
        switch event {
        case .command(let value): system(value)
        case .none: break
        }
    }
}
func submit(_ req: Request, service: Service) {
    let value = req.query.get(String.self, at: "command") ?? ""
    service.execute(CommandEvent.command(value))
}
func renderRaw(_ req: Request) -> Response {
    let value = req.query.get(String.self, at: "name") ?? ""
    return Response(status: .ok, body: .init(string: "<p>\(value)</p>"))
}
func renderLiteral(_ req: Request) -> Response {
    return Response(status: .ok, body: .init(string: "<p>safe</p>"))
}
"#,
    )]);
    assert!(
        has_unsanitized(&report, "swift.cmdi.system_libc", "execute"),
        "Vapor query data must cross enum and value wrappers into the service: {:#?}",
        report.findings
    );
    assert!(
        has_unsanitized(&report, "swift.xss.vapor_response_body_constructor", "renderRaw"),
        "raw Vapor HTML must remain reportable: {:#?}",
        report.findings
    );
    assert!(
        !has_unsanitized(
            &report,
            "swift.xss.vapor_response_body_constructor",
            "renderLiteral"
        ),
        "literal HTML must remain clean: {:#?}",
        report.findings
    );
}

#[test]
fn swift_lifecycle_state_controls_deserialization_and_xml_parsing() {
    let report = persisted_report(&[(
        "Sources/App/Parsers.swift",
        r#"
import Foundation

func decodeInsecure(_ data: Data) {
    let unarchiver = NSKeyedUnarchiver(forReadingFrom: data)
    unarchiver.requiresSecureCoding = false
    _ = unarchiver.decodeObject(forKey: "root")
}
func decodeSecure(_ data: Data) {
    let unarchiver = NSKeyedUnarchiver(forReadingFrom: data)
    unarchiver.requiresSecureCoding = true
    _ = unarchiver.decodeObject(forKey: "root")
}
func decodeOptionalInsecure(_ data: Data) {
    let unarchiver = try? NSKeyedUnarchiver(forReadingFrom: data)
    unarchiver?.requiresSecureCoding = false
    _ = unarchiver?.decodeObject(forKey: "root")
}
func decodeOptionalSecure(_ data: Data) {
    let unarchiver = try? NSKeyedUnarchiver(forReadingFrom: data)
    unarchiver?.requiresSecureCoding = true
    _ = unarchiver?.decodeObject(forKey: "root")
}
func parseExternal(_ data: Data) {
    let parser = XMLParser(data: data)
    parser.shouldResolveExternalEntities = true
    parser.parse()
}
func parseLocal(_ data: Data) {
    let parser = XMLParser(data: data)
    parser.shouldResolveExternalEntities = false
    parser.parse()
}
"#,
    )]);
    assert!(
        has_unsanitized(
            &report,
            "swift.deser.nskeyedunarchiver_decode_insecure_state",
            "decodeInsecure"
        ),
        "tainted archive plus insecure state must reach decodeObject: {:#?}",
        report.findings
    );
    assert!(
        !has_unsanitized(
            &report,
            "swift.deser.nskeyedunarchiver_decode_insecure_state",
            "decodeSecure"
        ),
        "secure coding state must reject the lifecycle sink: {:#?}",
        report.findings
    );
    assert!(
        has_unsanitized(
            &report,
            "swift.deser.nskeyedunarchiver_decode_insecure_state",
            "decodeOptionalInsecure"
        ),
        "optional try construction must retain typed archive provenance: {:#?}",
        report.findings
    );
    assert!(
        !has_unsanitized(
            &report,
            "swift.deser.nskeyedunarchiver_decode_insecure_state",
            "decodeOptionalSecure"
        ),
        "secure optional unarchiver state must remain clean: {:#?}",
        report.findings
    );
    assert!(
        has_unsanitized(
            &report,
            "swift.xxe.xmlparser_parse_external_entities",
            "parseExternal"
        ),
        "tainted XML plus enabled external entities must reach parse: {:#?}",
        report.findings
    );
    assert!(
        !has_unsanitized(
            &report,
            "swift.xxe.xmlparser_parse_external_entities",
            "parseLocal"
        ),
        "disabled external entities must reject the lifecycle sink: {:#?}",
        report.findings
    );
}

#[test]
fn swift_finite_literal_selection_and_process_shell_state_have_safe_twins() {
    let report = persisted_report(&[(
        "Sources/App/Execution.swift",
        r#"
import Foundation

func finiteCommand(_ key: String) -> String {
    return switch key {
    case "status": "status"
    case "version": "version"
    default: "help"
    }
}

func dynamicCommand(_ key: String) -> String {
    return switch key {
    case "status": "status"
    default: key
    }
}
func executeFinite(_ input: String) { system(finiteCommand(input)) }
func executeDynamic(_ input: String) { system(dynamicCommand(input)) }

func executeShell(_ input: String) throws {
    let process = Process()
    process.launchPath = "/bin/sh"
    process.arguments = ["-c", input]
    try process.run()
}
func executeDirect(_ input: String) throws {
    let process = Process()
    process.launchPath = "/usr/bin/printf"
    process.arguments = ["%s", input]
    try process.run()
}
func executeShellUrl(_ input: String) throws {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/bin/sh")
    process.arguments = ["-c", input]
    try process.run()
}
func executeDirectUrl(_ input: String) throws {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/usr/bin/printf")
    process.arguments = ["%s", input]
    try process.run()
}
func executeDynamicUrl(_ path: String) throws {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: path)
    try process.run()
}
"#,
    )]);
    assert!(
        !has_unsanitized(&report, "swift.cmdi.system_libc", "executeFinite"),
        "finite literal selection must remove the dynamic key: {:#?}",
        report.findings
    );
    assert!(
        has_unsanitized(&report, "swift.cmdi.system_libc", "executeDynamic"),
        "dynamic default arm must fail closed: {:#?}",
        report.findings
    );
    assert!(
        has_unsanitized(&report, "swift.cmdi.process_run", "executeShell"),
        "shell receiver state must be reportable: {:#?}",
        report.findings
    );
    assert!(
        !has_unsanitized(&report, "swift.cmdi.process_run", "executeDirect"),
        "direct argv must remain outside the shell boundary: {:#?}",
        report.findings
    );
    assert!(
        has_unsanitized(
            &report,
            "swift.cmdi.process_run_executable_url",
            "executeShellUrl"
        ),
        "an exact shell executable URL must be reportable: {:#?}",
        report.findings
    );
    assert!(
        !has_unsanitized(
            &report,
            "swift.cmdi.process_run_executable_url",
            "executeDirectUrl"
        ),
        "a direct executable URL must remain outside the shell boundary: {:#?}",
        report.findings
    );
    assert!(
        has_unsanitized(&report, "swift.cmdi.executableurl_write", "executeDynamicUrl"),
        "a tainted executable URL constructor argument must reach the typed member write: {:#?}",
        report.findings
    );
}

#[test]
fn kotlin_and_swift_interpolated_selections_keep_dynamic_input_tainted() {
    let report = persisted_report(&[
        (
            "src/main/kotlin/app/Selections.kt",
            r#"
package app
fun literalSelection(key: String) = when (key) {
    "first" -> "status"
    else -> "help"
}
fun interpolatedSelection(key: String) = when (key) {
    "first" -> "help"
    else -> "$key"
}
fun executeKotlinLiteral(input: String) { ProcessBuilder("sh", "-c", literalSelection(input)) }
fun executeKotlinInterpolated(input: String) { ProcessBuilder("sh", "-c", interpolatedSelection(input)) }
"#,
        ),
        (
            "Sources/App/Selections.swift",
            r##"
import Foundation
func interpolatedSelection(_ key: String) -> String {
    return switch key {
    case "first": "help"
    default: "\(key)"
    }
}
func rawInterpolatedSelection(_ key: String) -> String {
    return switch key {
    case "first": "help"
    default: #"\#(key)"#
    }
}
func executeSwiftInterpolated(_ input: String) { system(interpolatedSelection(input)) }
func executeSwiftRawInterpolated(_ input: String) { system(rawInterpolatedSelection(input)) }
"##,
        ),
    ]);
    assert!(
        !has_unsanitized(
            &report,
            "kotlin.cmdi.processbuilder_shell_command",
            "executeKotlinLiteral"
        ),
        "a complete literal selection must remain clean: {:#?}",
        report.findings
    );
    for (sink, function) in [
        (
            "kotlin.cmdi.processbuilder_shell_command",
            "executeKotlinInterpolated",
        ),
        ("swift.cmdi.system_libc", "executeSwiftInterpolated"),
        ("swift.cmdi.system_libc", "executeSwiftRawInterpolated"),
    ] {
        assert!(
            has_unsanitized(&report, sink, function),
            "{function}: interpolation is not a finite literal selection: {:#?}",
            report.findings
        );
    }
}

#[test]
fn swift_immutable_dictionary_selection_sanitizes_cross_file_sql_identifier() {
    let report = persisted_report(&[
        (
            "Sources/App/Controller.swift",
            r#"
import Vapor
struct SortInput: Content { let sort: String }

func handleSafe(_ req: Request, repo: OrderRepo) throws -> SQLQueryString {
    let input = try req.query.decode(SortInput.self)
    return repo.safe(sort: input.sort)
}

func handleUnsafe(_ req: Request, repo: OrderRepo) throws -> SQLQueryString {
    let input = try req.query.decode(SortInput.self)
    return repo.unsafe(sort: input.sort)
}
"#,
        ),
        (
            "Sources/App/OrderRepo.swift",
            r#"
import SQLKit
struct OrderRepo {
    private static let sortable = ["total": "total", "created_at": "created_at"]

    func safe(sort: String) -> SQLQueryString {
        let column = Self.sortable[sort] ?? "id"
        return SQLQueryString("SELECT * FROM records ORDER BY \(column)")
    }

    func unsafe(sort: String) -> SQLQueryString {
        return SQLQueryString("SELECT * FROM records ORDER BY " + sort)
    }
}
"#,
        ),
    ]);
    assert!(
        !has_unsanitized(&report, "swift.sqli.sqlkit_query_string_dynamic", "safe"),
        "an immutable finite dictionary lookup must remove selector taint: {:#?}",
        report.findings
    );
    assert!(
        has_unsanitized(&report, "swift.sqli.sqlkit_query_string_dynamic", "unsafe"),
        "a dynamic SQL identifier must remain reportable: {:#?}",
        report.findings
    );
}

#[test]
fn swift_sink_selection_is_monotonic_and_cache_reuse_is_exact() {
    let root = tempfile::tempdir_in(env!("CARGO_MANIFEST_DIR"))
        .expect("temporary persisted workspace inside the writable checkout");
    let source = r#"
import Foundation

func execute(_ path: String) throws {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: path)
    try process.run()
    system(path)
}
"#;
    let path = root.path().join("Sources/App/Execution.swift");
    std::fs::create_dir_all(path.parent().expect("fixture parent")).expect("create fixture directory");
    std::fs::write(path, source).expect("write fixture source");

    let registry = bonsai_adapters::all_languages_registry();
    let workspace =
        bonsai_workspace::Workspace::index(root.path(), registry).expect("index persisted workspace");
    let pack = bonsai_security::load_rulepack(&rules_root()).expect("load source-controlled rulepack");
    let options = TaintAnalysisOptions {
        include_inferred_sources: true,
        show_sanitized: true,
        ..Default::default()
    };
    let broad_first = bonsai_security::run_taint_analysis(&workspace, &pack, options.clone())
        .expect("run broad taint analysis");
    let write_only = bonsai_security::run_taint_analysis(
        &workspace,
        &pack,
        TaintAnalysisOptions {
            sink: Some("^swift\\.cmdi\\.executableurl_write$".to_string()),
            ..options.clone()
        },
    )
    .expect("run filtered taint analysis");
    let broad_reused =
        bonsai_security::run_taint_analysis(&workspace, &pack, options).expect("rerun broad taint analysis");

    let site_keys = |report: &TaintAnalysisReport| {
        report
            .findings
            .iter()
            .map(|finding| {
                (
                    finding.finding.sink.rule_id.clone(),
                    finding.finding.sink.file.clone(),
                    finding.finding.sink.line,
                    finding.finding.sink.column,
                )
            })
            .collect::<std::collections::BTreeSet<_>>()
    };
    let broad_first_sites = site_keys(&broad_first);
    let write_sites = site_keys(&write_only);
    let broad_reused_sites = site_keys(&broad_reused);
    assert!(!write_sites.is_empty(), "filtered write endpoint must be found");
    assert!(
        write_sites.is_subset(&broad_first_sites),
        "adding sink rules must never erase an exact endpoint: broad={broad_first_sites:#?} filtered={write_sites:#?}"
    );
    assert_eq!(
        broad_first_sites, broad_reused_sites,
        "reusing source-graph state must not change broad findings"
    );
}
