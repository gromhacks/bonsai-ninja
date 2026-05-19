//! Field-sensitive container semantics.
//!
//! These tests guard the distinction between dataflow and broad
//! container/control-flow taint. A value assigned to one key must not
//! taint sibling keys, even when the container is returned across a
//! function boundary or read through subscript syntax.

mod common;

use ahash::AHashMap;
use bonsai_callgraph::ResolvedCallGraph;
use bonsai_common::Precision;
use bonsai_db::AnalyzerDb;
use bonsai_idg::{workspace_adapter, IdgQueryService};
use bonsai_lang_api::AdapterArc;
use bonsai_lang_go::GoAdapter;
use bonsai_lang_python::PythonAdapter;
use bonsai_taint::{
    entry_taint_graph_from_idg, entry_taint_graph_from_idg_with_max_precision, interprocedural_taint,
    CallResultPassthrough, TokenSet,
};
use common::{build_db, cfg, func_id_or_none, seed, sink_reached};
use std::sync::Arc;

fn seed_idg_on(db: &AnalyzerDb) -> Arc<IdgQueryService> {
    let global = db.global_index();
    let cg = ResolvedCallGraph::build_with_file_info(
        global.as_ref(),
        |file| bonsai_resolve::alias_map_for_file(&db.imports_for(file)),
        |file| {
            bonsai_lang_api::alias_map_from_import_specs(&db.imports_for(file))
                .into_iter()
                .collect()
        },
        |file| {
            db.vfs()
                .path(file)
                .ok()
                .map(|path| path.to_string_lossy().into_owned())
        },
        |file| {
            db.adapter_for(file)
                .map(|adapter| adapter.capabilities().module_export_aliases)
                .unwrap_or(&[])
        },
        |file| db.adapter_for(file).map(|adapter| adapter.language_id().as_str()),
    );
    let ws = workspace_adapter::build_with_file_info(
        global.as_ref(),
        &cg,
        |_| AHashMap::new(),
        |file| db.adapter_for(file).map(|adapter| adapter.language_id().as_str()),
    );
    let svc = Arc::new(IdgQueryService::new(Arc::new(ws), global));
    db.set_idg_service(Arc::clone(&svc));
    svc
}

fn go_db(src: &str) -> AnalyzerDb {
    let adapter: AdapterArc = Arc::new(GoAdapter::new());
    build_db(adapter, &[("main.go", src)])
}

fn strings_fields_passthrough() -> Vec<CallResultPassthrough> {
    vec![CallResultPassthrough {
        callee: "strings.Fields".to_string(),
        input_arg_indices: vec![0],
        input_receiver: false,
    }]
}

#[test]
fn python_literal_subscript_read_stays_field_scoped() {
    let src = r#"
def entry(user):
    data = {"cmd": "safe", "user": user}
    cmd = data["cmd"]
    seen = data["user"]
    sink_user(seen)
    sink_cmd(cmd)
"#;
    let db = build_db(Arc::new(PythonAdapter::new()), &[("app.py", src)]);
    let entry = func_id_or_none(&db, "entry").expect("entry should index");
    let result = interprocedural_taint(entry, &seed(&["user"]), &cfg(), &db);
    assert!(
        sink_reached(&result, "sink_user"),
        "positive control must prove the user field still propagates: {:?}",
        result.tainted_calls
    );
    assert!(
        !sink_reached(&result, "sink_cmd"),
        "taint in data.user must not reach sibling data.cmd: {:?}",
        result.tainted_calls
    );
}

#[test]
fn python_tainted_branch_condition_does_not_taint_returned_container_fields() {
    let src = r#"
def entry(user):
    out = build(user)
    seen = out["user"]
    cmd = out["cmd"]
    sink_user(seen)
    sink_cmd(cmd)

def build(user):
    if user:
        return {"cmd": "safe", "user": user}
    return {"cmd": "safe", "user": "anon"}
"#;
    let db = build_db(Arc::new(PythonAdapter::new()), &[("app.py", src)]);
    let entry = func_id_or_none(&db, "entry").expect("entry should index");
    let result = interprocedural_taint(entry, &seed(&["user"]), &cfg(), &db);
    assert!(
        sink_reached(&result, "sink_user"),
        "returned user field must remain tainted: {:?}",
        result.tainted_calls
    );
    assert!(
        !sink_reached(&result, "sink_cmd"),
        "a tainted branch guard must not promote clean returned fields to out.*: {:?}",
        result.tainted_calls
    );
}

#[test]
fn python_dict_spread_arg_preserves_field_scope_across_call() {
    let src = r#"
def entry(raw_cmd, user):
    payload = {"cmd": raw_cmd, "user": user}
    envelope = {"kind": "run", **payload}
    run_pipeline(envelope)

def run_pipeline(envelope):
    seen = envelope["user"]
    cmd = envelope["cmd"]
    sink_user(seen)
    sink_cmd(cmd)
"#;
    let db = build_db(Arc::new(PythonAdapter::new()), &[("app.py", src)]);
    let entry = func_id_or_none(&db, "entry").expect("entry should index");
    let result = interprocedural_taint(entry, &seed(&["user"]), &cfg(), &db);

    assert!(
        sink_reached(&result, "sink_user"),
        "spread user field must still reach the matching sink: {:?}",
        result.tainted_calls
    );
    assert!(
        !sink_reached(&result, "sink_cmd"),
        "spread user field must not taint sibling cmd field across a call: {:?}",
        result.tainted_calls
    );
}

#[test]
fn python_ternary_dict_spread_preserves_field_scope_across_call() {
    let src = r#"
def entry(raw_cmd, mode, user):
    payload = (
        {"cmd": raw_cmd, "user": user}
        if len(raw_cmd) > 0
        else None
    )
    envelope = {"kind": "run", **payload, "length": len(raw_cmd)}
    envelope["mode"] = mode
    run_pipeline(envelope)

def run_pipeline(envelope):
    seen = envelope["user"]
    cmd = envelope["cmd"]
    sink_user(seen)
    sink_cmd(cmd)
"#;
    let db = build_db(Arc::new(PythonAdapter::new()), &[("app.py", src)]);
    let entry = func_id_or_none(&db, "entry").expect("entry should index");
    let result = interprocedural_taint(entry, &seed(&["user"]), &cfg(), &db);

    assert!(
        sink_reached(&result, "sink_user"),
        "ternary/spread user field must reach the matching sink: {:?}",
        result.tainted_calls
    );
    assert!(
        !sink_reached(&result, "sink_cmd"),
        "ternary/spread user field must not taint sibling cmd field across a call: {:?}",
        result.tainted_calls
    );
}

#[test]
fn python_returned_dict_spread_rest_does_not_taint_explicit_cmd_field() {
    let src = r#"
def entry(cmd, user):
    expanded = {"arg": cmd, "user": user}
    normalized = normalize(expanded, user=user)
    valid = validate_payload(normalized)
    seen = valid["user"]
    out = valid["cmd"]
    sink_user(seen)
    sink_cmd(out)

def normalize(item, user="anon"):
    payload = item.get("arg") or ""
    footer = "user={u}".format(u=user)
    return {
        "user": user,
        "tag": "arg",
        "value": payload.strip(),
        "footer": footer,
    }

def validate_payload(payload):
    v = payload["value"]
    rest = {"user": payload["user"], "footer": payload["footer"]}
    return {"kind": "arg", "cmd": v, **rest}
"#;
    let db = build_db(Arc::new(PythonAdapter::new()), &[("app.py", src)]);
    let idg = seed_idg_on(&db);
    let entry = func_id_or_none(&db, "entry").expect("entry should index");
    let mut user_tokens = TokenSet::default();
    user_tokens.insert("user".to_string());
    let result = entry_taint_graph_from_idg(entry, &user_tokens, None, &[], &[], &db, idg.as_ref());

    assert!(
        result
            .tainted_calls
            .iter()
            .any(|call| call.name.ends_with("sink_user")),
        "returned spread rest field must reach the matching user sink: {:?}",
        result.tainted_calls
    );
    assert!(
        !result
            .tainted_calls
            .iter()
            .any(|call| call.name.ends_with("sink_cmd")),
        "tainted rest fields must not taint explicit cmd field in returned dict: {:?}",
        result.tainted_calls
    );
}

#[test]
fn python_constructor_property_read_keeps_receiver_fields_scoped() {
    let src = r#"
class Repository:
    def __init__(self, data):
        self._data = data

    @property
    def data(self):
        return self._data

    def persist(self):
        seen = self.data["user"]
        cmd = self.data["cmd"]
        sink_user(seen)
        sink_cmd(cmd)

class AuditedRepository(Repository):
    def __init__(self, data, who="anon"):
        super().__init__(data)
        self.who = who

    @property
    def data(self):
        return self._data

def entry(cmd, user):
    valid = {"cmd": cmd, "user": user}
    repo = AuditedRepository(valid, who=user)
    repo.persist()
"#;
    let db = build_db(Arc::new(PythonAdapter::new()), &[("app.py", src)]);
    let entry = func_id_or_none(&db, "entry").expect("entry should index");
    let cmd_result = interprocedural_taint(entry, &seed(&["cmd"]), &cfg(), &db);
    assert!(
        sink_reached(&cmd_result, "sink_cmd"),
        "constructor-stored command field must reach the matching property read: {:?}",
        cmd_result.tainted_calls
    );
    assert!(
        !sink_reached(&cmd_result, "sink_user"),
        "constructor-stored command field must not taint sibling user reads: {:?}",
        cmd_result.tainted_calls
    );

    let result = interprocedural_taint(entry, &seed(&["user"]), &cfg(), &db);
    assert!(
        sink_reached(&result, "sink_user"),
        "constructor-stored receiver field must reach the matching property read: {:?}",
        result.tainted_calls
    );
    assert!(
        !sink_reached(&result, "sink_cmd"),
        "constructor-stored receiver field must not taint sibling property field reads: {:?}",
        result.tainted_calls
    );
}

#[test]
fn python_idg_constructor_super_receiver_mutation_stays_field_scoped() {
    let src = r#"
class Transaction:
    def perform(self, cmd):
        sink_cmd(cmd)

class Repository:
    def __init__(self, data):
        self._data = data

    @property
    def data(self):
        return self._data

    def persist(self):
        seen = self.data["user"]
        cmd = self.data["cmd"]
        sink_user(seen)
        tx = Transaction()
        tx.perform(cmd)

class AuditedRepository(Repository):
    def __init__(self, data, who="anon"):
        super().__init__(data)
        self.who = who

def entry(cmd, user):
    valid = {"cmd": cmd, "user": user}
    repo = AuditedRepository(valid, who=user)
    repo.persist()
"#;
    let db = build_db(Arc::new(PythonAdapter::new()), &[("app.py", src)]);
    let idg = seed_idg_on(&db);
    let entry = func_id_or_none(&db, "entry").expect("entry should index");

    let mut cmd_tokens = TokenSet::default();
    cmd_tokens.insert("cmd".to_string());
    let cmd_graph = entry_taint_graph_from_idg(entry, &cmd_tokens, None, &[], &[], &db, idg.as_ref());
    assert!(
        cmd_graph
            .tainted_calls
            .iter()
            .any(|call| call.name.ends_with("sink_cmd")),
        "IDG must carry command taint through super().__init__ receiver storage: {:?}",
        cmd_graph.tainted_calls
    );
    assert!(
        !cmd_graph
            .tainted_calls
            .iter()
            .any(|call| call.name.ends_with("sink_user")),
        "IDG command taint must not promote to sibling user field: {:?}",
        cmd_graph.tainted_calls
    );

    let mut user_tokens = TokenSet::default();
    user_tokens.insert("user".to_string());
    let user_graph = entry_taint_graph_from_idg(entry, &user_tokens, None, &[], &[], &db, idg.as_ref());
    assert!(
        user_graph
            .tainted_calls
            .iter()
            .any(|call| call.name.ends_with("sink_user")),
        "IDG must carry user taint through the matching receiver field: {:?}",
        user_graph.tainted_calls
    );
    assert!(
        !user_graph
            .tainted_calls
            .iter()
            .any(|call| call.name.ends_with("sink_cmd")),
        "IDG user taint must not reach sibling command field: {:?}",
        user_graph.tainted_calls
    );
}

#[test]
fn python_idg_returned_dict_get_and_spread_fields_stay_scoped() {
    let src = r#"
def entry(cmd, user):
    expanded = {"arg": cmd, "user": user}
    normalized = normalize(expanded, user=user)
    valid = validate_payload(normalized)
    seen = valid["user"]
    out = valid["cmd"]
    sink_user(seen)
    sink_cmd(out)

def normalize(item, user="anon"):
    payload = item.get("flag") or item.get("arg") or ""
    footer = "user={u}".format(u=user)
    return {
        "user": user,
        "tag": "arg",
        "value": payload.strip(),
        "footer": footer,
    }

def validate_payload(payload):
    v = payload["value"]
    rest = {"user": payload["user"], "footer": payload["footer"]}
    return {"kind": "arg", "cmd": v, **rest}
"#;
    let db = build_db(Arc::new(PythonAdapter::new()), &[("app.py", src)]);
    let idg = seed_idg_on(&db);
    let entry = func_id_or_none(&db, "entry").expect("entry should index");

    let mut cmd_tokens = TokenSet::default();
    cmd_tokens.insert("cmd".to_string());
    let cmd_graph = entry_taint_graph_from_idg(entry, &cmd_tokens, None, &[], &[], &db, idg.as_ref());
    assert!(
        cmd_graph
            .tainted_calls
            .iter()
            .any(|call| call.name.ends_with("sink_cmd")),
        "IDG must carry item.get('arg') through returned dict fields into cmd: {:?}",
        cmd_graph.tainted_calls
    );
    assert!(
        !cmd_graph
            .tainted_calls
            .iter()
            .any(|call| call.name.ends_with("sink_user")),
        "IDG command taint must not promote into returned spread user fields: {:?}",
        cmd_graph.tainted_calls
    );

    let mut user_tokens = TokenSet::default();
    user_tokens.insert("user".to_string());
    let user_graph = entry_taint_graph_from_idg(entry, &user_tokens, None, &[], &[], &db, idg.as_ref());
    assert!(
        user_graph
            .tainted_calls
            .iter()
            .any(|call| call.name.ends_with("sink_user")),
        "IDG must carry returned spread user fields into the matching sink: {:?}",
        user_graph.tainted_calls
    );
    assert!(
        !user_graph
            .tainted_calls
            .iter()
            .any(|call| call.name.ends_with("sink_cmd")),
        "IDG user taint must not reach sibling returned cmd field: {:?}",
        user_graph.tainted_calls
    );
}

#[test]
fn go_composite_literal_fields_stay_field_scoped() {
    let src = r#"
package main

type Envelope struct {
    Cmd string
    User string
}

type Repository struct {
    data Envelope
}

type AuditedRepository struct {
    Repository *Repository
}

func entry(cmd string, user string) {
    data := Envelope{Cmd: cmd, User: user}
    repo := &AuditedRepository{Repository: &Repository{data: data}}
    sinkUser(repo.Repository.data.User)
    sinkCmd(repo.Repository.data.Cmd)
}
"#;
    let db = build_db(Arc::new(GoAdapter::new()), &[("main.go", src)]);
    let entry = func_id_or_none(&db, "entry").expect("entry should index");
    let result = interprocedural_taint(entry, &seed(&["user"]), &cfg(), &db);

    assert!(
        sink_reached(&result, "sinkUser"),
        "Go struct literal must propagate the matching field: {:?}",
        result.tainted_calls
    );
    assert!(
        !sink_reached(&result, "sinkCmd"),
        "Go struct literal field taint must not promote to sibling fields: {:?}",
        result.tainted_calls
    );
}

#[test]
fn go_idg_call_result_source_reaches_matching_struct_field_only() {
    let src = r#"
package main

type Envelope struct {
    Cmd string
    User string
}

func source() string { return "" }

func entry(user string) {
    raw := source()
    env := Envelope{Cmd: raw, User: user}
    orchestrate(env)
}

func orchestrate(env Envelope) {
    cmd := env.Cmd
    seen := env.User
    sinkUser(seen)
    execute(cmd)
}

func execute(cmd string) {
    sinkCmd(cmd)
}
"#;
    let db = go_db(src);
    let idg = seed_idg_on(&db);
    let entry = func_id_or_none(&db, "entry").expect("entry should index");

    let raw_seed = idg.read_or_write_nodes_for_names(entry, &["raw".to_string()]);
    let raw_calls = idg.tainted_call_args_in_closure(&raw_seed);
    assert!(
        raw_calls.iter().any(|(_, span, idx)| span.start > 0 && *idx == 0),
        "raw call-result source should reach at least one downstream arg: {raw_calls:?}"
    );

    let mut raw_tokens = TokenSet::default();
    raw_tokens.insert("raw".to_string());
    let raw_graph = entry_taint_graph_from_idg(entry, &raw_tokens, None, &[], &[], &db, idg.as_ref());
    assert!(
        raw_graph
            .tainted_calls
            .iter()
            .any(|call| call.name.ends_with("sinkCmd")),
        "raw must reach the command sink through env.Cmd: {:?}",
        raw_graph.tainted_calls
    );

    let mut user_tokens = TokenSet::default();
    user_tokens.insert("user".to_string());
    let user_graph = entry_taint_graph_from_idg(entry, &user_tokens, None, &[], &[], &db, idg.as_ref());
    assert!(
        user_graph
            .tainted_calls
            .iter()
            .any(|call| call.name.ends_with("sinkUser")),
        "user must still reach the matching user sink: {:?}",
        user_graph.tainted_calls
    );
    assert!(
        !user_graph
            .tainted_calls
            .iter()
            .any(|call| call.name.ends_with("sinkCmd")),
        "user must not reach sibling env.Cmd command sink: {:?}",
        user_graph.tainted_calls
    );
}

#[test]
fn go_idg_channel_range_flow_is_value_precise() {
    let src = r#"
package main

import "strings"

func source() string { return "" }

func entry(user string) {
    raw := source()
    for tok := range tokenize(raw) {
        execute(tok)
    }
    sinkUser(user)
}

func tokenize(cmd string) <-chan string {
    out := make(chan string)
    for _, part := range strings.Fields(cmd) {
        out <- part
    }
    return out
}

func execute(cmd string) {
    sinkCmd(cmd)
}
"#;
    let db = go_db(src);
    let idg = seed_idg_on(&db);
    let entry = func_id_or_none(&db, "entry").expect("entry should index");

    let mut raw_tokens = TokenSet::default();
    raw_tokens.insert("raw".to_string());
    let passthroughs = strings_fields_passthrough();
    let raw_graph = entry_taint_graph_from_idg_with_max_precision(
        entry,
        &raw_tokens,
        None,
        &[],
        &[],
        &passthroughs,
        &[],
        Some(Precision::Narrowed),
        &db,
        idg.as_ref(),
    );
    assert!(
        raw_graph
            .tainted_calls
            .iter()
            .any(|call| call.name.ends_with("sinkCmd")),
        "raw must flow through channel send/range value into the command sink: {:?}",
        raw_graph.tainted_calls
    );
    assert!(
        !raw_graph
            .tainted_calls
            .iter()
            .any(|call| call.name.ends_with("sinkUser")),
        "explicit local raw seed must not taint the unrelated user parameter: {:?}",
        raw_graph.tainted_calls
    );

    let mut user_tokens = TokenSet::default();
    user_tokens.insert("user".to_string());
    let user_graph = entry_taint_graph_from_idg_with_max_precision(
        entry,
        &user_tokens,
        None,
        &[],
        &[],
        &passthroughs,
        &[],
        Some(Precision::Narrowed),
        &db,
        idg.as_ref(),
    );
    assert!(
        user_graph
            .tainted_calls
            .iter()
            .any(|call| call.name.ends_with("sinkUser")),
        "user must still reach the matching user sink: {:?}",
        user_graph.tainted_calls
    );
    assert!(
        !user_graph
            .tainted_calls
            .iter()
            .any(|call| call.name.ends_with("sinkCmd")),
        "user must not flow into the ranged command value: {:?}",
        user_graph.tainted_calls
    );
}

#[test]
fn go_range_over_external_split_requires_configured_passthrough() {
    let src = r#"
package main

import "strings"

func entry(cmd string) {
    for _, part := range strings.Fields(cmd) {
        sinkPart(part)
    }
}
"#;
    let db = go_db(src);
    let idg = seed_idg_on(&db);
    let entry = func_id_or_none(&db, "entry").expect("entry should index");

    let mut cmd_tokens = TokenSet::default();
    cmd_tokens.insert("cmd".to_string());
    let plain_graph = entry_taint_graph_from_idg(entry, &cmd_tokens, None, &[], &[], &db, idg.as_ref());
    assert!(
        !plain_graph
            .tainted_calls
            .iter()
            .any(|call| call.name.ends_with("sinkPart")),
        "unconfigured external split results must not be treated as value passthroughs: {:?}",
        plain_graph.tainted_calls
    );

    let passthroughs = strings_fields_passthrough();
    let configured_graph = entry_taint_graph_from_idg_with_max_precision(
        entry,
        &cmd_tokens,
        None,
        &[],
        &[],
        &passthroughs,
        &[],
        Some(Precision::Narrowed),
        &db,
        idg.as_ref(),
    );
    assert!(
        configured_graph
            .tainted_calls
            .iter()
            .any(|call| call.name.ends_with("sinkPart")),
        "configured split passthrough should taint the ranged element: {:?}",
        configured_graph.tainted_calls
    );
}

#[test]
fn python_annotated_subscript_read_uses_specific_field_not_carrier() {
    let src = r#"
def entry(user):
    envelope = {"cmd": "safe", "user": user}
    run(envelope)

def run(envelope):
    cmd: str = envelope["cmd"]
    seen: str = envelope["user"]
    sink_user(seen)
    sink_cmd(cmd)
"#;
    let db = build_db(Arc::new(PythonAdapter::new()), &[("app.py", src)]);
    let entry = func_id_or_none(&db, "entry").expect("entry should index");
    let result = interprocedural_taint(entry, &seed(&["user"]), &cfg(), &db);

    assert!(
        sink_reached(&result, "sink_user"),
        "annotated subscript read must preserve the matching field: {:?}",
        result.tainted_calls
    );
    assert!(
        !sink_reached(&result, "sink_cmd"),
        "annotated subscript read of cmd must not match envelope.user: {:?}",
        result.tainted_calls
    );
}
