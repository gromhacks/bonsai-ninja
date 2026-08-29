//! Exact Dart callback-source ownership. Provider callback signatures live in
//! typing rules; the Dart frontend contributes only parsed callback and
//! receiver-root facts.

use bonsai_security::{load_rulepack, match_rules_against_facts, run_taint_analysis, TaintAnalysisOptions};
use std::path::{Path, PathBuf};
use std::sync::Arc;

fn rules_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("security-patterns")
}

fn matches(source: &str) -> (Vec<String>, Vec<(String, Vec<String>)>) {
    let ws = bonsai_workspace::Workspace::new(bonsai_adapters::all_languages_registry());
    let file = ws
        .vfs()
        .write("functions.dart".to_string(), Arc::<str>::from(source));
    let pack = load_rulepack(&rules_root()).expect("load source-controlled rulepack");
    let selected = pack
        .all_rules()
        .into_iter()
        .filter(|rule| {
            matches!(
                rule.id.as_str(),
                "dart.cloud.firebase_oncall_data"
                    | "dart.typing.firebase_run_functions_callback"
                    | "dart.grpc.service_method_request"
            )
        })
        .collect::<Vec<_>>();
    let facts = ws
        .db()
        .decl_index(file)
        .expect("Dart declaration index")
        .defs
        .iter()
        .flat_map(|decl| {
            decl.flow_events.iter().filter_map(|event| match event {
                bonsai_lang_api::FlowEvent::Call {
                    name, receiver_types, ..
                } => Some((name.clone(), receiver_types.clone())),
                _ => None,
            })
        })
        .collect::<Vec<_>>();
    let ids = match_rules_against_facts(&ws, &selected)
        .into_iter()
        .map(|hit| hit.rule_id)
        .collect();
    (ids, facts)
}

#[test]
fn run_functions_callback_types_the_exact_firebase_receiver_root() {
    let (ids, facts) = matches(
        r#"
import 'package:firebase_functions/firebase_functions.dart';
void main(List<String> args) {
  runFunctions((firebase) {
    firebase.https.onCall(name: 'lookup', handler: (request) async => sink(request.data));
  });
}
"#,
    );
    assert!(
        ids.iter().any(|id| id == "dart.cloud.firebase_oncall_data"),
        "typing must connect runFunctions callback param 0 to the onCall receiver root: ids={ids:?}, calls={facts:#?}"
    );
}

#[test]
fn same_named_application_callback_does_not_gain_firebase_type() {
    let (ids, facts) = matches(
        r#"
import 'package:firebase_functions/firebase_functions.dart';
class LocalHttps { void onCall({required String name, required Function handler}) {} }
class LocalFirebase { final https = LocalHttps(); }
void register(void Function(LocalFirebase) callback) => callback(LocalFirebase());
void main() {
  register((firebase) {
    firebase.https.onCall(name: 'lookup', handler: (request) => sink(request));
  });
}
"#,
    );
    assert!(
        ids.iter().all(|id| id != "dart.cloud.firebase_oncall_data"),
        "same-named local callback must fail the provider typing proof: ids={ids:?}, calls={facts:#?}"
    );
}

#[test]
fn grpc_generated_service_payload_uses_signature_facts_not_parameter_names() {
    let (ids, _) = matches(
        r#"
import 'package:grpc/grpc.dart';
class GreeterService extends GreeterServiceBase {
  @override
  Future<Reply> sayHello(ServiceCall context, HelloRequest payload) async {
    sink(payload);
    return Reply();
  }
}
"#,
    );
    assert!(
        ids.iter().any(|id| id == "dart.grpc.service_method_request"),
        "generated gRPC request parameter must match independently of its binding and message type: {ids:?}"
    );

    for collision in [
        r#"
import 'package:grpc/grpc.dart';
class LocalHandler extends LocalBase {
  @override
  void handle(ServiceCall context, Object payload) { sink(payload); }
}
"#,
        r#"
import 'package:grpc/grpc.dart';
class LocalService extends LocalServiceBase {
  @override
  void handle(Object context, Object payload) { sink(payload); }
}
"#,
    ] {
        let (ids, _) = matches(collision);
        assert!(
            ids.iter().all(|id| id != "dart.grpc.service_method_request"),
            "class and typed-context collision must fail closed: {ids:?}"
        );
    }
}

#[test]
fn grpc_generated_service_payload_enters_the_idg() {
    let ws = bonsai_workspace::Workspace::new(bonsai_adapters::all_languages_registry());
    ws.vfs().write(
        "service.dart".to_string(),
        Arc::<str>::from(
            r#"
import 'package:grpc/grpc.dart';
import 'dart:io';
class GreeterService extends GreeterServiceBase {
  @override
  Future<Reply> run(ServiceCall context, CommandRequest payload) async {
    Process.runSync('sh', ['-c', payload.command]);
    return Reply();
  }
}
"#,
        ),
    );
    let pack = load_rulepack(&rules_root()).expect("load source-controlled rulepack");
    let findings = run_taint_analysis(
        &ws,
        &pack,
        TaintAnalysisOptions {
            source: Some("dart.grpc.service_method_request".to_string()),
            ..TaintAnalysisOptions::default()
        },
    )
    .expect("Dart gRPC taint analysis");
    assert!(
        findings
            .findings
            .iter()
            .any(|finding| finding.finding.source.rule_id == "dart.grpc.service_method_request"),
        "compiler-proven request parameter must seed a complete source-to-sink path: {findings:#?}"
    );
}
