//! End-to-end security-flow regressions for dynamic and native language
//! value transports that are easy to lose during adapter lowering.

use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("repository root")
        .to_path_buf()
}

fn bin_path() -> PathBuf {
    option_env!("CARGO_BIN_EXE_bonsai-ninja")
        .map(PathBuf::from)
        .or_else(|| {
            let debug = repo_root().join("target/debug/bonsai-ninja");
            debug.exists().then_some(debug)
        })
        .or_else(|| {
            let release = repo_root().join("target/release/bonsai-ninja");
            release.exists().then_some(release)
        })
        .expect("bonsai-ninja test binary")
}

fn rules_dir() -> PathBuf {
    repo_root().join("security-patterns")
}

fn temp_dir(tag: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    for attempt in 0..100 {
        let path = Path::new("/tmp").join(format!(
            "bonsai-dynamic-native-{tag}-{}-{nanos}-{attempt}",
            std::process::id()
        ));
        match fs::create_dir(&path) {
            Ok(()) => return path,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => panic!("create {}: {error}", path.display()),
        }
    }
    panic!("could not allocate temporary directory for {tag}")
}

fn write_file(root: &Path, relative: &str, source: &str) {
    let path = root.join(relative);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("fixture parent");
    }
    fs::write(path, source).expect("fixture source");
}

fn taint_rows(workspace: &Path, source: &str, sink: &str, cache: Option<&Path>) -> Vec<Value> {
    let mut command = Command::new(bin_path());
    command.arg("--no-progress");
    command
        .arg("security")
        .arg(workspace)
        .args([
            "taint-analysis",
            "--profile",
            "all",
            "--rules-dir",
            rules_dir().to_str().expect("rules path"),
            "--source",
            source,
            "--sink",
            sink,
            "--format",
            "json",
            "--all",
            "--no-color",
        ])
        .env("NO_COLOR", "1");
    let ephemeral_cache;
    let cache = match cache {
        Some(cache) => cache,
        None => {
            ephemeral_cache = temp_dir("ephemeral-cache");
            &ephemeral_cache
        }
    };
    command.env("BONSAI_WORKSPACE_DIR", cache);
    let output = command.output().expect("run taint analysis");
    assert!(
        output.status.success(),
        "taint analysis failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let value: Value = serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "invalid taint JSON: {error}\n{}",
            String::from_utf8_lossy(&output.stdout)
        )
    });
    assert_eq!(
        value.get("analysis_complete").and_then(Value::as_bool),
        Some(true),
        "taint analysis returned findings from an incomplete compiler snapshot:\n{}",
        serde_json::to_string_pretty(&value).expect("render incomplete analysis")
    );
    assert!(
        value
            .get("analysis_incomplete_reasons")
            .and_then(Value::as_array)
            .is_some_and(Vec::is_empty),
        "complete taint analysis retained incomplete reasons:\n{}",
        serde_json::to_string_pretty(&value).expect("render incomplete reasons")
    );
    value
        .get("findings")
        .or_else(|| value.get("rows"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
}

fn assert_finding(rows: &[Value], fragments: &[&str]) {
    let rendered = serde_json::to_string_pretty(rows).expect("render rows");
    assert!(
        !rows.is_empty(),
        "expected a finding containing {fragments:?}:\n{rendered}"
    );
    for fragment in fragments {
        assert!(
            rendered.contains(fragment),
            "finding did not contain `{fragment}`:\n{rendered}"
        );
    }
}

#[test]
fn dart_shelf_values_cross_helpers_aggregates_and_cascade_receiver_state() {
    let workspace = temp_dir("dart-shelf-transports");
    write_file(
        &workspace,
        "pubspec.yaml",
        "name: adapter_flow_test\ndependencies:\n  shelf: any\n  xml: any\n",
    );
    write_file(
        &workspace,
        "lib/app.dart",
        r#"import 'dart:io';
import 'package:shelf/shelf.dart';
import 'package:xml/xml.dart';

String queryValue(String value) => value.trim().toLowerCase();

Future<ProcessResult> launch(String value) =>
    Process.run('sh', ['-c', 'printf %s ' + value]);

class XmlCarrier {
  String payload = '<safe/>';
  XmlDocument parse() => XmlDocument.parse(payload);
}

Future<void> handle(Request request) async {
  final value = request.url.queryParameters['q'] ?? '';
  await launch(queryValue(value));
  final carrier = XmlCarrier()..payload = await request.readAsString();
  carrier.parse();
}

Future<void> clean() async {
  await launch('fixed');
  final carrier = XmlCarrier()..payload = '<safe/>';
  carrier.parse();
}
"#,
    );

    let command_rows = taint_rows(
        &workspace,
        "^dart\\.shelf\\.request_url$",
        "^dart\\.cmdi\\.process_run_shell_args$",
        None,
    );
    assert_finding(
        &command_rows,
        &["dart.shelf.request_url", "dart.cmdi.process_run_shell_args"],
    );

    let xml_rows = taint_rows(
        &workspace,
        "^dart\\.http\\.request_read_as_string$",
        "^dart\\.xxe\\.xml_document_parse$",
        None,
    );
    assert_finding(
        &xml_rows,
        &["dart.http.request_read_as_string", "dart.xxe.xml_document_parse"],
    );
}

#[test]
fn php_psr7_query_state_crosses_request_scoped_objects() {
    let workspace = temp_dir("php-psr7-state");
    write_file(
        &workspace,
        "composer.json",
        r#"{"require":{"psr/http-message":"*"}}"#,
    );
    write_file(
        &workspace,
        "src/Handler.php",
        r#"<?php
use Psr\Http\Message\ServerRequestInterface;

final class RequestScope {
    private array $query = [];
    public function capture(ServerRequestInterface $request): void {
        $this->query = $request->getQueryParams();
    }
    public function resource(): string {
        return $this->query['resource'];
    }
}

final class Loader {
    public function load(RequestScope $scope): string {
        return file_get_contents($scope->resource());
    }
}

function handle(ServerRequestInterface $request): string {
    $scope = new RequestScope();
    $scope->capture($request);
    return (new Loader())->load($scope);
}

function clean(): string {
    return file_get_contents('/srv/app/banner.txt');
}
"#,
    );

    let rows = taint_rows(
        &workspace,
        "^php\\.source\\.slim_request_get_params$",
        "^php\\.path\\.file_get_contents$",
        None,
    );
    assert_finding(
        &rows,
        &["php.source.slim_request_get_params", "php.path.file_get_contents"],
    );
}

#[test]
fn lua_openresty_values_survive_helper_returns_and_html_concatenation() {
    let workspace = temp_dir("lua-openresty-html");
    write_file(
        &workspace,
        "app.lua",
        r#"local function query_value()
  local args = ngx.req.get_uri_args()
  return args.q
end

local function page(value)
  return "<main>" .. value .. "</main>"
end

local function handle()
  ngx.print(page(query_value()))
end

local function clean()
  ngx.print(page("fixed"))
end

return { handle = handle, clean = clean }
"#,
    );

    let rows = taint_rows(
        &workspace,
        "^lua\\.source\\.openresty_get_uri_args$",
        "^lua\\.xss\\.ngx_print$",
        None,
    );
    assert_finding(&rows, &["lua.source.openresty_get_uri_args", "lua.xss.ngx_print"]);
}

#[test]
fn rust_axum_bytes_and_iterator_closures_reach_deserialization_and_html_sinks_with_warm_reuse() {
    let workspace = temp_dir("rust-axum-transports");
    let cache = temp_dir("rust-axum-cache");
    write_file(
        &workspace,
        "Cargo.toml",
        "[package]\nname = \"adapter-flow-test\"\nversion = \"0.1.0\"\n[dependencies]\naxum = \"*\"\nserde_yaml = \"*\"\n",
    );
    write_file(
        &workspace,
        "src/lib.rs",
        r#"use axum::body::Bytes;
use axum::extract::Query;
use axum::response::Html;
use serde_yaml::Value;

pub fn parse(body: Bytes) {
    let text = String::from_utf8(body.to_vec()).unwrap();
    let _: Value = serde_yaml::from_str(&text).unwrap();
}

pub fn render(Query(values): Query<Vec<String>>) -> Html<String> {
    let items = values
        .into_iter()
        .map(|value| format!("<li>{value}</li>"))
        .collect::<String>();
    Html(format!("<ul>{items}</ul>"))
}

pub fn clean() -> Html<String> {
    let _: Value = serde_yaml::from_str("name: safe").unwrap();
    Html("<p>safe</p>".to_string())
}
"#,
    );

    let deser_rows = taint_rows(
        &workspace,
        "^rust\\.axum\\.body_bytes$",
        "^rust\\.deser\\.serde_yaml_from_str$",
        Some(&cache),
    );
    assert_finding(
        &deser_rows,
        &["rust.axum.body_bytes", "rust.deser.serde_yaml_from_str"],
    );

    let html_rows = taint_rows(
        &workspace,
        "^rust\\.axum\\.query$",
        "^rust\\.xss\\.axum_html_response$",
        Some(&cache),
    );
    assert_finding(&html_rows, &["rust.axum.query", "rust.xss.axum_html_response"]);

    let warm_deser_rows = taint_rows(
        &workspace,
        "^rust\\.axum\\.body_bytes$",
        "^rust\\.deser\\.serde_yaml_from_str$",
        Some(&cache),
    );
    assert_eq!(
        serde_json::to_value(&deser_rows).expect("cold rows"),
        serde_json::to_value(&warm_deser_rows).expect("warm rows"),
        "persisted analysis reuse must preserve exact findings"
    );
}
