//! Compiler-to-IDG regressions for dynamic/native value transports.

mod common;

use bonsai_lang_api::AdapterArc;
use bonsai_taint::{ensure_idg_service, interprocedural_taint};
use common::{build_db, cfg, func_id_or_none, seed, sink_received_arg_index};
use std::sync::Arc;

fn run(
    adapter: AdapterArc,
    file: &str,
    source: &str,
    entry: &str,
    seeds: &[&str],
) -> bonsai_taint::InterTaintResult {
    let db = build_db(adapter, &[(file, source)]);
    let entry = func_id_or_none(&db, entry).unwrap_or_else(|| panic!("missing {entry}"));
    interprocedural_taint(entry, &seed(seeds), &cfg(), &db)
}

#[test]
fn dart_helper_aggregate_and_cascade_receiver_transports_reach_calls() {
    let result = run(
        Arc::new(bonsai_lang_dart::DartAdapter::new()),
        "app.dart",
        r#"
class Request {
  Uri url = Uri();
  String body = '';
  Future<String> readAsString() async => this.body;
}
class Uri { Map<String, String> queryParameters = {}; }
class XmlDocument { static void parse(String value) {} }
class Carrier {
  String payload = '';
  void parse() { XmlDocument.parse(payload); }
}
class Process { static void run(String executable, List<String> args) {} }

String query(String value) => value;
Future<void> handle(Request request, String input) async {
  Process.run('sh', ['-c', query(input)]);
  request.body = input;
  final carrier = Carrier()..payload = await request.readAsString();
  carrier.parse();
}
"#,
        "handle",
        &["request", "request.url", "request.url.queryParameters", "input"],
    );
    assert!(
        sink_received_arg_index(&result, "Process.run", 1),
        "Dart list aggregate lost its helper-derived input: {:#?}",
        result.tainted_calls
    );
    assert!(
        result.tainted_calls.iter().any(|call| {
            call.name == "carrier.payload"
                && call.kind == bonsai_taint::TaintedCallKind::Write
                && call.tainted_args.iter().any(|arg| arg.index == 0)
        }),
        "Dart cascade field write lost its awaited call result: {:#?}",
        result.tainted_calls
    );
}

#[test]
fn php_method_receiver_field_call_result_reaches_direct_consumer() {
    let result = run(
        Arc::new(bonsai_lang_php::PhpAdapter::new()),
        "app.php",
        r#"<?php
interface Incoming { public function getQueryParams(); }
final class Scope {
  private array $query = [];
  public function capture(Incoming $request): void {
    $this->query = $request->getQueryParams();
  }
  public function resource(): string { return $this->query['resource']; }
}
function handle(Incoming $request): string {
  $scope = new Scope();
  $scope->capture($request);
  return file_get_contents($scope->resource());
}
"#,
        "handle",
        &["request", "$request"],
    );
    assert!(
        sink_received_arg_index(&result, "file_get_contents", 0),
        "PHP receiver state did not reach the direct consumer: {:#?}",
        result.tainted_calls
    );
}

#[test]
fn lua_helper_return_and_string_concatenation_reach_response_call() {
    let result = run(
        Arc::new(bonsai_lang_lua::LuaAdapter::new()),
        "app.lua",
        r#"
local function page(value)
  return "<main>" .. value .. "</main>"
end
function handle(input)
  ngx.print(page(input))
end
"#,
        "handle",
        &["input"],
    );
    assert!(
        sink_received_arg_index(&result, "ngx.print", 0),
        "Lua concatenated helper result did not reach the response call: {:#?}",
        result.tainted_calls
    );
}

#[test]
fn rust_byte_conversion_and_iterator_closure_outputs_reach_consumers() {
    let bytes = run(
        Arc::new(bonsai_lang_rust::RustAdapter::new()),
        "bytes.rs",
        r#"
struct Bytes;
impl Bytes { fn to_vec(self) -> Vec<u8> { Vec::new() } }
struct Reader;
impl Reader { fn from_str(_: &str) -> Self { Self } }
fn parse(body: Bytes) {
  let text = String::from_utf8(body.to_vec()).unwrap();
  let _reader = Reader::from_str(&text);
}
"#,
        "parse",
        &["body"],
    );
    assert!(
        sink_received_arg_index(&bytes, "Reader::from_str", 0),
        "Rust Bytes-to-String conversion lost the input: {:#?}",
        bytes.tainted_calls
    );

    let html_source = r#"
struct Html<T>(T);
fn emit(_: String) {}
fn render(values: Vec<String>) -> Html<String> {
  let items = values
    .into_iter()
    .map(|value| format!("<li>{value}</li>"))
    .collect::<String>();
  emit(format!("<ul>{items}</ul>"));
  Html(format!("<ul>{items}</ul>"))
}
"#;
    let db = build_db(
        Arc::new(bonsai_lang_rust::RustAdapter::new()),
        &[("html.rs", html_source)],
    );
    let entry = func_id_or_none(&db, "render").expect("render declaration");
    let html_span = db
        .global_index()
        .decl_of(bonsai_common::SymbolId::new(entry.raw()))
        .and_then(|decl| {
            decl.flow_events.iter().find_map(|event| match event {
                bonsai_lang_api::FlowEvent::Call { span, name, .. } if name == "Html" => Some(*span),
                _ => None,
            })
        })
        .expect("Html call");
    let idg = ensure_idg_service(&db);
    let target_nodes = idg.nodes_at_span(entry, html_span);
    let relevance = idg.target_relevance_with_max_precision(&target_nodes, None, None);
    let target_points = target_nodes
        .iter()
        .filter_map(|node| idg.resolve_point(*node))
        .collect::<Vec<_>>();
    let param_nodes = idg.param_nodes_of(entry);
    let param_points = param_nodes
        .iter()
        .filter_map(|node| idg.resolve_point(*node))
        .collect::<Vec<_>>();
    let forward = idg.forward_closure(&param_nodes);
    let forward_points = forward
        .iter()
        .filter_map(|node| idg.resolve_point(*node))
        .collect::<Vec<_>>();
    let reaches_target = target_nodes.iter().any(|target| forward.contains(target));
    assert!(
        relevance.admits_any(&param_nodes) && reaches_target,
        "the iterator input must reach the Html argument in both directions; targets={target_points:#?}, params={param_points:#?}, forward={forward_points:#?}, backward_admits={}, forward_reaches={reaches_target}",
        relevance.admits_any(&param_nodes)
    );
    let html = interprocedural_taint(entry, &seed(&["values"]), &cfg(), &db);
    assert!(
        sink_received_arg_index(&html, "emit", 0),
        "Rust iterator closure composition lost the collection input: {:#?}",
        html.tainted_calls
    );
}
