//! Objective-C and Swift source-boundary proofs from exact compiler facts
//! through rule matching and the sparse IDG taint closure.

use std::collections::BTreeSet;
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

fn source_ids(path: &str, source: &str) -> BTreeSet<String> {
    let ws = workspace(path, source);
    let pack = bonsai_security::load_rulepack(&rules_root()).expect("load source-controlled rulepack");
    bonsai_security::source_inventory(&ws, &pack, Default::default())
        .expect("source inventory")
        .into_iter()
        .map(|source| source.rule_id)
        .collect()
}

fn taint_source_ids(path: &str, source: &str) -> BTreeSet<String> {
    let ws = workspace(path, source);
    let pack = bonsai_security::load_rulepack(&rules_root()).expect("load source-controlled rulepack");
    bonsai_security::run_taint_analysis(&ws, &pack, Default::default())
        .expect("taint analysis")
        .findings
        .into_iter()
        .map(|finding| finding.finding.source.rule_id)
        .collect()
}

fn taint_sink_ids(path: &str, source: &str) -> BTreeSet<String> {
    let ws = workspace(path, source);
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
fn objective_c_exact_property_and_delegate_boundaries_match() {
    let ids = source_ids(
        "Inputs.m",
        r#"
#import <Foundation/Foundation.h>
void process_values(void) {
  id argvProperty = [NSProcessInfo processInfo].arguments;
  id argvMessage = [[NSProcessInfo processInfo] arguments];
  id envProperty = [NSProcessInfo processInfo].environment;
  id envMessage = [[NSProcessInfo processInfo] environment];
}
@implementation Client
- (void)URLSession:(NSURLSession *)session dataTask:(NSURLSessionDataTask *)task didReceiveData:(NSData *)chunk { consume(chunk); }
- (void)URLSession:(NSURLSession *)session downloadTask:(NSURLSessionDownloadTask *)task didFinishDownloadingToURL:(NSURL *)location { consume(location); }
- (void)URLSession:(NSURLSession *)session task:(NSURLSessionTask *)task willPerformHTTPRedirection:(NSHTTPURLResponse *)response newRequest:(NSURLRequest *)redirected completionHandler:(void (^)(NSURLRequest *))completion { consume(redirected); }
@end
"#,
    );
    for expected in [
        "objc.source.nsprocessinfo_arguments",
        "objc.source.nsprocessinfo_arguments_message",
        "objc.source.nsprocessinfo_environment",
        "objc.source.nsprocessinfo_environment_message",
        "objc.source.nsurlsession_delegate_data",
        "objc.source.nsurlsession_download_delegate_location",
        "objc.source.nsurlrequest_param",
    ] {
        assert!(
            ids.contains(expected),
            "missing Objective-C source {expected}; got {ids:?}"
        );
    }
}

#[test]
fn objective_c_same_named_properties_and_parameters_remain_clean() {
    let ids = source_ids(
        "Collisions.m",
        r#"
#import <Foundation/Foundation.h>
@interface ProcessState : NSObject
@property id processInfo;
@property id arguments;
@property id environment;
@end
id read(ProcessState *state) {
  id a = state.processInfo.arguments;
  id e = state.processInfo.environment;
  return a ?: e;
}
void consumeData(NSData *chunk) { }
void consumeURL(NSURL *location) { }
void consumeRequest(NSURLRequest *redirected) { }
"#,
    );
    let forbidden = ids
        .iter()
        .filter(|id| {
            id.starts_with("objc.source.nsprocessinfo_")
                || id.as_str() == "objc.source.nsurlsession_delegate_data"
                || id.as_str() == "objc.source.nsurlsession_download_delegate_location"
                || id.as_str() == "objc.source.nsurlrequest_param"
        })
        .collect::<Vec<_>>();
    assert!(
        forbidden.is_empty(),
        "Objective-C collision sources: {forbidden:?}"
    );
}

#[test]
fn objective_c_property_and_delegate_sources_reach_idg_sinks() {
    let ids = taint_source_ids(
        "Flows.m",
        r#"
#import <Foundation/Foundation.h>
void process_flow(void) {
  id arguments = [NSProcessInfo processInfo].arguments;
  system(arguments);
}
@implementation Client
- (void)URLSession:(NSURLSession *)session dataTask:(NSURLSessionDataTask *)task didReceiveData:(NSData *)chunk { system(chunk); }
- (void)URLSession:(NSURLSession *)session task:(NSURLSessionTask *)task willPerformHTTPRedirection:(NSHTTPURLResponse *)response newRequest:(NSURLRequest *)redirected completionHandler:(void (^)(NSURLRequest *))completion { system(redirected); }
@end
"#,
    );
    for expected in [
        "objc.source.nsprocessinfo_arguments",
        "objc.source.nsurlsession_delegate_data",
        "objc.source.nsurlrequest_param",
    ] {
        assert!(
            ids.contains(expected),
            "Objective-C source {expected} must reach system(); got {ids:?}"
        );
    }
}

#[test]
fn objective_c_multipart_message_argument_reaches_exact_sink() {
    let source = r#"
#import <GCDWebServer/GCDWebServer.h>
void test(id input) {
  [GCDWebServerDataResponse responseWithStatusCode:500 text:input];
}
"#;
    let ws = workspace("ErrorResponse.m", source);
    let file = ws.vfs().all_files()[0];
    let declarations = ws.db().decl_index(file).expect("Objective-C compiler facts");
    let call = declarations
        .defs
        .iter()
        .find(|decl| decl.name == "test")
        .and_then(|decl| {
            decl.flow_events.iter().find_map(|event| match event {
                bonsai_lang_api::FlowEvent::Call { name, args, .. } => Some((name, args)),
                _ => None,
            })
        })
        .expect("multipart message call");
    assert_eq!(
        call.0, "GCDWebServerDataResponse.responseWithStatusCode:text:",
        "the adapter must preserve the complete selector"
    );
    assert_eq!(
        call.1.len(),
        2,
        "the adapter must preserve both selector arguments"
    );
    assert!(
        call.1[1].source_names.iter().any(|name| name == "input"),
        "the compiler must attribute the dynamic second argument exactly: {:#?}",
        call.1[1]
    );
    let pack = bonsai_security::load_rulepack(&rules_root()).expect("load source-controlled rulepack");
    let owner = pack
        .find_rule_by_id("objc.info_disclosure.gcdwebserver_error_response")
        .expect("GCDWebServer sink rule");
    let mut static_owner = owner.clone();
    static_owner.constraints = Default::default();
    let static_hits = bonsai_security::match_rule_against_facts(&ws, &static_owner);
    let mut ungated_owner = static_owner.clone();
    ungated_owner.packages.clear();
    let ungated_hits = bonsai_security::match_rule_against_facts(&ws, &ungated_owner);
    assert!(
        !ungated_hits.is_empty(),
        "the compiler call must satisfy the exact target before package and taint gates: {static_owner:#?}"
    );
    assert!(
        !static_hits.is_empty(),
        "the parsed framework import must satisfy the exact package gate; ungated={ungated_hits:#?}"
    );
    let inventory = bonsai_security::sink_inventory(&ws, &pack, Default::default())
        .expect("sink inventory")
        .into_iter()
        .map(|matched| matched.rule_id)
        .collect::<BTreeSet<_>>();
    assert!(
        inventory.contains("objc.info_disclosure.gcdwebserver_error_response"),
        "the exact multipart selector must match its rule; got {inventory:?}"
    );
    let ids = taint_sink_ids("ErrorResponse.m", source);
    assert!(
        ids.contains("objc.info_disclosure.gcdwebserver_error_response"),
        "the second argument of a multipart Objective-C selector must reach its exact sink; got {ids:?}"
    );
}

#[test]
fn swift_typed_read_and_websocket_callback_boundaries_match() {
    let source = r#"
import UIKit
import Vapor
func clipboard(board: UIPasteboard) {
  consume(board.string)
  consume(UIPasteboard.general.url)
}
func request(req: Request) { consume(req.body); consume(req.headers) }
func sockets(socket: WebSocket) {
  socket.onText { ws, text in consume(text) }
  socket.onBinary({ ws, data in consume(data) })
}
"#;
    let ws = workspace("Inputs.swift", source);
    let pack = bonsai_security::load_rulepack(&rules_root()).expect("load source-controlled rulepack");
    let matches =
        bonsai_security::source_inventory(&ws, &pack, Default::default()).expect("source inventory");
    let ids = matches
        .iter()
        .map(|matched| matched.rule_id.clone())
        .collect::<BTreeSet<_>>();
    for expected in [
        "swift.uipasteboard_value_read",
        "swift.uipasteboard_general_value_read",
        "swift.vapor.request_body",
        "swift.vapor.request_headers",
        "swift.websocket_on_text",
        "swift.websocket_on_binary",
    ] {
        assert!(
            ids.contains(expected),
            "missing Swift source {expected}; got {ids:?}"
        );
    }
    let typed_clipboard_reads = matches
        .iter()
        .filter(|matched| matched.rule_id == "swift.uipasteboard_value_read")
        .map(|matched| matched.match_text.as_str())
        .collect::<BTreeSet<_>>();
    assert!(
        typed_clipboard_reads.contains("board.string"),
        "the typed-instance pasteboard rule must cover board.string; got {typed_clipboard_reads:?}"
    );
    assert!(
        typed_clipboard_reads.contains("board.string"),
        "the typed-instance pasteboard rule must cover board.string; got {typed_clipboard_reads:?}"
    );
    let singleton_clipboard_reads = matches
        .iter()
        .filter(|matched| matched.rule_id == "swift.uipasteboard_general_value_read")
        .map(|matched| matched.match_text.as_str())
        .collect::<BTreeSet<_>>();
    assert!(
        singleton_clipboard_reads.contains("UIPasteboard.general.url"),
        "the imported singleton-chain rule must cover UIPasteboard.general.url; got {singleton_clipboard_reads:?}"
    );
}

#[test]
fn swift_same_named_receivers_and_named_callbacks_remain_clean() {
    let ids = source_ids(
        "Collisions.swift",
        r#"
import UIKit
import Vapor
struct LocalBoard { let string: String; let url: String }
struct LocalRequest { let body: String; let headers: [String] }
struct LocalSocket {
  func onText(_ handler: (LocalSocket, String) -> Void) { }
  func onBinary(_ handler: (LocalSocket, [UInt8]) -> Void) { }
}
func clean(board: LocalBoard, req: LocalRequest, socket: LocalSocket) {
  consume(board.string); consume(board.url); consume(req.body); consume(req.headers)
  socket.onText { ws, text in consume(text) }
  socket.onBinary { ws, data in consume(data) }
}
func named(socket: WebSocket, handler: (WebSocket, String) -> Void) {
  socket.onText(handler)
}
"#,
    );
    let forbidden = ids
        .iter()
        .filter(|id| {
            id.starts_with("swift.uipasteboard_")
                || id.starts_with("swift.vapor.request_")
                || id.starts_with("swift.websocket_")
        })
        .collect::<Vec<_>>();
    assert!(forbidden.is_empty(), "Swift collision sources: {forbidden:?}");
}

#[test]
fn swift_typed_reads_and_inline_callback_sources_reach_idg_sinks() {
    let ids = taint_source_ids(
        "Flows.swift",
        r#"
import UIKit
import Vapor
func clipboard(board: UIPasteboard) { system(board.string) }
func request(req: Request) { system(req.body) }
func sockets(socket: WebSocket) {
  socket.onText { ws, text in system(text) }
  socket.onBinary { ws, data in system(data) }
}
"#,
    );
    for expected in [
        "swift.uipasteboard_value_read",
        "swift.vapor.request_body",
        "swift.websocket_on_text",
        "swift.websocket_on_binary",
    ] {
        assert!(
            ids.contains(expected),
            "Swift source {expected} must reach system(); got {ids:?}"
        );
    }
}
