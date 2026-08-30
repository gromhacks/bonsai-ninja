use std::path::{Path, PathBuf};
use std::sync::Arc;

fn rules_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("security-patterns")
}

fn analyze(source: &str) -> bonsai_security::TaintAnalysisReport {
    let workspace = bonsai_workspace::Workspace::new(bonsai_adapters::all_languages_registry());
    workspace
        .vfs()
        .write("app.py".to_string(), Arc::<str>::from(source));
    let pack = bonsai_security::load_rulepack(&rules_root()).expect("load source-controlled rulepack");
    bonsai_security::run_taint_analysis(&workspace, &pack, Default::default())
        .expect("run Python taint analysis")
}

#[test]
fn asyncio_to_thread_execution_contract_comes_from_typing_rule() {
    let report = analyze(
        r#"
import asyncio
import os
from flask import request

async def run():
    command = request.args.get("command", "")
    return await asyncio.to_thread(execute, command)

def execute(command):
    return os.system(command)
"#,
    );
    assert!(
        report.findings.iter().any(|finding| {
            finding.finding.source.rule_id == "python.flask.request_args_get"
                && finding.finding.sink.rule_id == "python.cmdi.os_system"
        }),
        "the rule-owned callback invocation must connect the exact callable argument: {:#?}",
        report.findings
    );
}

#[test]
fn same_named_local_method_does_not_gain_asyncio_execution_semantics() {
    let report = analyze(
        r#"
import os
from flask import request

class Local:
    def to_thread(self, callback, value):
        return value

async def run(local):
    command = request.args.get("command", "")
    return await local.to_thread(os.system, command)
"#,
    );
    assert!(
        report.findings.is_empty(),
        "an untyped same-named method must not invent callback execution: {:#?}",
        report.findings
    );
}

#[test]
fn path_containment_proof_follows_rule_compiled_callback_forwarding() {
    let report = analyze(
        r#"
import asyncio
import os
from flask import request

BASE = "/srv/data"

def read_bytes(path):
    with open(path, "rb") as handle:
        return handle.read()

async def load():
    name = request.args.get("name", "")
    base = os.path.realpath(BASE)
    candidate = os.path.realpath(os.path.join(base, name))
    if not candidate.startswith(base + os.sep):
        raise FileNotFoundError(name)
    return await asyncio.to_thread(read_bytes, candidate)
"#,
    );
    assert!(
        report
            .findings
            .iter()
            .all(|finding| finding.finding.sink.rule_id != "python.path.open"),
        "a compiler-proven forwarded callback argument must retain the caller's containment proof: {:#?}",
        report.findings
    );
}

#[test]
fn callback_forwarding_without_a_containment_proof_remains_unsafe() {
    let report = analyze(
        r#"
import asyncio
from flask import request

def read_bytes(path):
    with open(path, "rb") as handle:
        return handle.read()

async def load():
    name = request.args.get("name", "")
    return await asyncio.to_thread(read_bytes, name)
"#,
    );
    assert!(
        report
            .findings
            .iter()
            .any(|finding| finding.finding.sink.rule_id == "python.path.open"),
        "callback execution semantics must not fabricate a containment proof: {:#?}",
        report.findings
    );
}
