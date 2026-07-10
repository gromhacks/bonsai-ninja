//! Field-sensitive container semantics.
//!
//! These tests guard the distinction between dataflow and broad
//! container/control-flow taint. A value assigned to one key must not
//! taint sibling keys, even when the container is returned across a
//! function boundary or read through subscript syntax.

mod common;

use ahash::AHashSet;
use bonsai_callgraph::ResolvedCallGraph;
use bonsai_common::Precision;
use bonsai_db::AnalyzerDb;
use bonsai_idg::{workspace_adapter, IdgQueryService, TransferOptions};
use bonsai_lang_api::AdapterArc;
use bonsai_lang_go::GoAdapter;
use bonsai_lang_javascript::JavaScriptAdapter;
use bonsai_lang_objc::ObjCAdapter;
use bonsai_lang_python::PythonAdapter;
use bonsai_lang_rust::RustAdapter;
use bonsai_lang_solidity::SolidityAdapter;
use bonsai_taint::{
    entry_taint_graph_from_idg, entry_taint_graph_from_idg_with_max_precision,
    entry_taint_graph_from_idg_with_target_funcs_and_max_precision, interprocedural_taint,
    CallResultPassthrough, TokenSet,
};
use common::{build_db, cfg, func_id_or_none, seed, sink_reached};
use std::sync::Arc;

fn seed_idg_on(db: &AnalyzerDb) -> Arc<IdgQueryService> {
    let transfer_options = TransferOptions {
        include_diagnostic_field_flows: false,
        include_receiver_method_propagation: false,
        ..TransferOptions::default()
    };
    let (ws, global) = build_idg_workspace_on(db, &transfer_options);
    let svc = Arc::new(IdgQueryService::new(ws, global));
    db.set_idg_service(Arc::clone(&svc));
    svc
}

fn build_idg_workspace_on(
    db: &AnalyzerDb,
    transfer_options: &TransferOptions,
) -> (Arc<bonsai_idg::IdgWorkspace>, Arc<bonsai_index::GlobalIndex>) {
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
    let ws = workspace_adapter::build_with_file_info_and_options(
        global.as_ref(),
        &cg,
        |file| bonsai_resolve::semantic_import_binding_map_for_file(&db.imports_for(file)),
        |file| db.adapter_for(file).map(|adapter| adapter.language_id().as_str()),
        transfer_options,
    );
    (Arc::new(ws), global)
}

fn go_db(src: &str) -> AnalyzerDb {
    let adapter: AdapterArc = Arc::new(GoAdapter::new());
    build_db(adapter, &[("main.go", src)])
}

fn javascript_db(src: &str) -> AnalyzerDb {
    let adapter: AdapterArc = Arc::new(JavaScriptAdapter::new());
    build_db(adapter, &[("app.js", src)])
}

fn objc_db(src: &str) -> AnalyzerDb {
    let adapter: AdapterArc = Arc::new(ObjCAdapter::new());
    build_db(adapter, &[("app.m", src)])
}

fn solidity_db(src: &str) -> AnalyzerDb {
    let adapter: AdapterArc = Arc::new(SolidityAdapter::new());
    build_db(adapter, &[("Demo.sol", src)])
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
fn rust_idg_newtype_constructor_receiver_state_stays_field_scoped() {
    let src = r#"
struct Envelope {
    cmd: String,
    user: String,
}

struct Repository {
    data: Envelope,
}

impl Repository {
    fn new(data: Envelope) -> Self {
        Self { data }
    }

    fn cmd(&self) -> String {
        self.data.cmd.clone()
    }

    fn run(&self) {
        let cmd = self.cmd();
        execute(cmd);
    }
}

struct AuditedRepository(Repository);

impl AuditedRepository {
    fn wrap(data: Envelope) -> Self {
        Self(Repository::new(data))
    }

    fn run(&self) {
        self.0.run();
    }
}

fn entry(raw: String, user: String) {
    let valid = Envelope { cmd: raw, user };
    let repo = AuditedRepository::wrap(valid);
    repo.run();
}

fn execute(cmd: String) {
    sink_cmd(cmd);
}

fn sink_cmd(_cmd: String) {}
"#;
    let db = build_db(Arc::new(RustAdapter::new()), &[("main.rs", src)]);
    let idg = seed_idg_on(&db);
    let entry = func_id_or_none(&db, "entry").expect("entry should index");
    let target_funcs = ["entry", "wrap", "new", "run", "cmd", "execute", "sink_cmd"]
        .into_iter()
        .filter_map(|name| func_id_or_none(&db, name))
        .collect::<AHashSet<_>>();

    let mut raw_tokens = TokenSet::default();
    raw_tokens.insert("raw".to_string());
    let raw_graph = entry_taint_graph_from_idg_with_target_funcs_and_max_precision(
        entry,
        &raw_tokens,
        None,
        &[],
        &[],
        &[],
        &[],
        Some(&target_funcs),
        Some(Precision::Narrowed),
        &db,
        idg.as_ref(),
    );
    assert!(
        raw_graph
            .tainted_calls
            .iter()
            .any(|call| call.name.ends_with("sink_cmd")),
        "Rust newtype constructor state should carry valid.cmd to sink_cmd: {:?}",
        raw_graph.tainted_calls
    );

    let mut user_tokens = TokenSet::default();
    user_tokens.insert("user".to_string());
    let user_graph = entry_taint_graph_from_idg_with_target_funcs_and_max_precision(
        entry,
        &user_tokens,
        None,
        &[],
        &[],
        &[],
        &[],
        Some(&target_funcs),
        Some(Precision::Narrowed),
        &db,
        idg.as_ref(),
    );
    assert!(
        !user_graph
            .tainted_calls
            .iter()
            .any(|call| call.name.ends_with("sink_cmd")),
        "Rust newtype constructor state must not promote valid.user into sink_cmd: {:?}",
        user_graph.tainted_calls
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
fn javascript_idg_object_getter_super_chain_reaches_matching_field_only() {
    let src = r#"
function source() { return ""; }

function entry(user) {
  const raw = source();
  const envelope = { cmd: raw, user };
  return orchestrate(envelope);
}

function orchestrate(envelope) {
  const { cmd, user, ...rest } = envelope;
  sinkUser(user);
  const valid = { ...rest, user, cmd };
  return persist(valid);
}

class Repository {
  constructor(data) {
    this._data = data;
  }

  get cmd() {
    return this._data.cmd;
  }

  run() {
    const c = this.cmd;
    return execute(c);
  }
}

class AuditedRepository extends Repository {
  constructor(data) {
    super(data);
  }

  run() {
    return super.run();
  }
}

function persist(data) {
  const repo = new AuditedRepository(data);
  return repo.run();
}

function execute(cmd) {
  sinkCmd(cmd);
}

function sinkUser(user) {}
function sinkCmd(cmd) {}
"#;
    let db = javascript_db(src);
    let idg = seed_idg_on(&db);
    let entry = func_id_or_none(&db, "entry").expect("entry should index");

    let mut raw_tokens = TokenSet::default();
    raw_tokens.insert("raw".to_string());
    let raw_graph = entry_taint_graph_from_idg(entry, &raw_tokens, None, &[], &[], &db, idg.as_ref());
    assert!(
        raw_graph
            .tainted_calls
            .iter()
            .any(|call| call.name.ends_with("sinkCmd")),
        "raw must reach the command sink through object fields, constructor state, getter, and super: {:?}",
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
        "positive control must keep user field propagation available: {:?}",
        user_graph.tainted_calls
    );
    assert!(
        !user_graph
            .tainted_calls
            .iter()
            .any(|call| call.name.ends_with("sinkCmd")),
        "user must not reach sibling cmd sink through the getter chain: {:?}",
        user_graph.tainted_calls
    );
}

#[test]
fn objc_idg_dictionary_literal_fields_stay_field_scoped() {
    let src = r#"
void sinkCmd(NSString *cmd);
void sinkUser(NSString *user);

void entry(NSString *cmd, NSString *user) {
    NSDictionary *envelope = @{
        @"cmd": cmd,
        @"user": user
    };
    orchestrate(envelope);
}

void orchestrate(NSDictionary *envelope) {
    NSString *cmd = envelope[@"cmd"];
    NSString *seen = envelope[@"user"];
    sinkCmd(cmd);
    sinkUser(seen);
}
"#;
    let db = objc_db(src);
    let idg = seed_idg_on(&db);
    let entry = func_id_or_none(&db, "entry").expect("entry should index");

    let mut cmd_tokens = TokenSet::default();
    cmd_tokens.insert("cmd".to_string());
    let cmd_graph = entry_taint_graph_from_idg(entry, &cmd_tokens, None, &[], &[], &db, idg.as_ref());
    assert!(
        cmd_graph
            .tainted_calls
            .iter()
            .any(|call| call.name.ends_with("sinkCmd")),
        "ObjC dictionary cmd field must reach the matching sink: {:?}",
        cmd_graph.tainted_calls
    );
    assert!(
        !cmd_graph
            .tainted_calls
            .iter()
            .any(|call| call.name.ends_with("sinkUser")),
        "ObjC dictionary cmd field must not taint sibling user reads: {:?}",
        cmd_graph.tainted_calls
    );

    let mut user_tokens = TokenSet::default();
    user_tokens.insert("user".to_string());
    let user_graph = entry_taint_graph_from_idg(entry, &user_tokens, None, &[], &[], &db, idg.as_ref());
    assert!(
        user_graph
            .tainted_calls
            .iter()
            .any(|call| call.name.ends_with("sinkUser")),
        "ObjC dictionary user field must reach the matching sink: {:?}",
        user_graph.tainted_calls
    );
    assert!(
        !user_graph
            .tainted_calls
            .iter()
            .any(|call| call.name.ends_with("sinkCmd")),
        "ObjC dictionary user field must not taint sibling cmd reads: {:?}",
        user_graph.tainted_calls
    );
}

#[test]
fn objc_idg_static_subscript_return_reads_matching_dictionary_field() {
    let src = r#"
void sinkCmd(NSString *cmd);
void sinkUser(NSString *user);

void entry(NSString *cmd, NSString *user) {
    NSDictionary *envelope = @{
        @"cmd": cmd,
        @"user": user
    };
    NSString *selected = pick_cmd(envelope);
    sinkCmd(selected);
    sinkUser(user);
}

NSString *pick_cmd(NSDictionary *envelope) {
    return envelope[@"cmd"];
}
"#;
    let db = objc_db(src);
    let idg = seed_idg_on(&db);
    let entry = func_id_or_none(&db, "entry").expect("entry should index");

    let mut cmd_tokens = TokenSet::default();
    cmd_tokens.insert("cmd".to_string());
    let cmd_graph = entry_taint_graph_from_idg(entry, &cmd_tokens, None, &[], &[], &db, idg.as_ref());
    assert!(
        cmd_graph
            .tainted_calls
            .iter()
            .any(|call| call.name.ends_with("sinkCmd")),
        "ObjC static subscript return must carry the matching dictionary field: {:?}",
        cmd_graph.tainted_calls
    );
    assert!(
        !cmd_graph
            .tainted_calls
            .iter()
            .any(|call| call.name.ends_with("sinkUser")),
        "ObjC command field return must not taint sibling user sinks: {:?}",
        cmd_graph.tainted_calls
    );

    let mut user_tokens = TokenSet::default();
    user_tokens.insert("user".to_string());
    let user_graph = entry_taint_graph_from_idg(entry, &user_tokens, None, &[], &[], &db, idg.as_ref());
    assert!(
        user_graph
            .tainted_calls
            .iter()
            .any(|call| call.name.ends_with("sinkUser")),
        "ObjC user seed must still reach its matching sink: {:?}",
        user_graph.tainted_calls
    );
    assert!(
        !user_graph
            .tainted_calls
            .iter()
            .any(|call| call.name.ends_with("sinkCmd")),
        "ObjC user dictionary field must not flow through a cmd subscript return: {:?}",
        user_graph.tainted_calls
    );
}

#[test]
fn objc_dynamic_subscript_literal_write_does_not_clean_whole_buffer() {
    let src = r#"
void sink(NSString *value);

void entry(char *buf) {
    buf[strcspn(buf, "\n")] = 0;
    NSString *raw = @(buf);
    sink(raw);
}
"#;
    let db = objc_db(src);
    let idg = seed_idg_on(&db);
    let entry = func_id_or_none(&db, "entry").expect("entry should index");

    let mut tokens = TokenSet::default();
    tokens.insert("buf".to_string());
    let graph = entry_taint_graph_from_idg(entry, &tokens, None, &[], &[], &db, idg.as_ref());
    assert!(
        graph.tainted_calls.iter().any(|call| call.name.ends_with("sink")),
        "dynamic element literal write must not sanitize the whole buffer: {:?}",
        graph.tainted_calls
    );
}

#[test]
fn solidity_idg_struct_literal_fields_stay_field_scoped() {
    let src = r#"
contract Demo {
    struct Envelope {
        bytes cmd;
        bytes user;
    }

    function entry(bytes memory cmd, bytes memory user) public {
        Envelope memory envelope = Envelope({
            cmd: cmd,
            user: user
        });
        orchestrate(envelope);
    }

    function orchestrate(Envelope memory envelope) internal {
        sinkCmd(envelope.cmd);
        sinkUser(envelope.user);
    }
}
"#;
    let db = solidity_db(src);
    let idg = seed_idg_on(&db);
    let entry = func_id_or_none(&db, "entry").expect("entry should index");

    let mut cmd_tokens = TokenSet::default();
    cmd_tokens.insert("cmd".to_string());
    let cmd_graph = entry_taint_graph_from_idg(entry, &cmd_tokens, None, &[], &[], &db, idg.as_ref());
    assert!(
        cmd_graph
            .tainted_calls
            .iter()
            .any(|call| call.name.ends_with("sinkCmd")),
        "Solidity struct literal cmd field must reach the matching sink: {:?}",
        cmd_graph.tainted_calls
    );
    assert!(
        !cmd_graph
            .tainted_calls
            .iter()
            .any(|call| call.name.ends_with("sinkUser")),
        "Solidity struct literal cmd field must not taint sibling user reads: {:?}",
        cmd_graph.tainted_calls
    );

    let mut user_tokens = TokenSet::default();
    user_tokens.insert("user".to_string());
    let user_graph = entry_taint_graph_from_idg(entry, &user_tokens, None, &[], &[], &db, idg.as_ref());
    assert!(
        user_graph
            .tainted_calls
            .iter()
            .any(|call| call.name.ends_with("sinkUser")),
        "Solidity struct literal user field must reach the matching sink: {:?}",
        user_graph.tainted_calls
    );
    assert!(
        !user_graph
            .tainted_calls
            .iter()
            .any(|call| call.name.ends_with("sinkCmd")),
        "Solidity struct literal user field must not taint sibling cmd reads: {:?}",
        user_graph.tainted_calls
    );
}

#[test]
fn qualified_field_taint_does_not_promote_to_bare_tail_parameter() {
    let src = r#"
contract Demo {
    struct Envelope {
        bytes cmd;
        bytes user;
    }

    function entry(bytes memory raw, bytes memory cmd) public {
        Envelope memory envelope = Envelope({
            cmd: raw,
            user: raw
        });
        orchestrate(envelope, cmd);
    }

    function orchestrate(Envelope memory envelope, bytes memory cmd) internal {
        sinkPayload(envelope.cmd);
        sinkBare(cmd);
    }
}
"#;
    let db = solidity_db(src);
    let idg = seed_idg_on(&db);
    let entry = func_id_or_none(&db, "entry").expect("entry should index");

    let mut raw_tokens = TokenSet::default();
    raw_tokens.insert("raw".to_string());
    let graph = entry_taint_graph_from_idg(entry, &raw_tokens, None, &[], &[], &db, idg.as_ref());
    assert!(
        graph
            .tainted_calls
            .iter()
            .any(|call| call.name.ends_with("sinkPayload")),
        "qualified field taint must still reach the matching field sink: {:?}",
        graph.tainted_calls
    );
    assert!(
        !graph
            .tainted_calls
            .iter()
            .any(|call| call.name.ends_with("sinkBare")),
        "envelope.cmd must not taint a distinct bare cmd parameter: {:?}",
        graph.tainted_calls
    );
}

#[test]
fn solidity_projected_cmd_arg_does_not_taint_sibling_event_kind() {
    let src = r#"
contract Demo {
    event Orchestrated(uint8 kind, uint256 length);

    struct Envelope {
        uint8 kind;
        bytes cmd;
        uint256 length;
    }

    function entry(bytes memory raw) public {
        Envelope memory envelope = Envelope({
            kind: 1,
            cmd: raw,
            length: raw.length
        });
        orchestrate(envelope.cmd, uint8(envelope.kind));
    }

    function orchestrate(bytes memory cmd, uint8 kind) internal {
        bytes memory routed = bytes(cmd);
        uint256 len = routed.length + 0;
        emit Orchestrated(kind, len);
    }
}
"#;
    let db = solidity_db(src);
    let idg = seed_idg_on(&db);
    let entry = func_id_or_none(&db, "entry").expect("entry should index");

    let mut tokens = TokenSet::default();
    tokens.insert("envelope.cmd".to_string());
    let graph = entry_taint_graph_from_idg(entry, &tokens, None, &[], &[], &db, idg.as_ref());
    assert!(
        graph.tainted_calls.iter().any(|call| {
            call.name == "orchestrate"
                && call
                    .tainted_args
                    .iter()
                    .any(|arg| arg.index == 0 && arg.value_text == "envelope.cmd")
        }),
        "envelope.cmd should still taint the routed command argument: {:?}",
        graph.tainted_calls
    );
    assert!(
        !graph.tainted_calls.iter().any(|call| {
            call.name == "emit"
                && call
                    .tainted_args
                    .iter()
                    .any(|arg| arg.index == 0 && arg.value_text == "kind")
        }),
        "envelope.cmd must not taint the sibling event kind argument: {:?}",
        graph.tainted_calls
    );
    assert!(
        !graph.tainted_calls.iter().any(|call| {
            call.name == "Orchestrated"
                && call
                    .tainted_args
                    .iter()
                    .any(|arg| arg.index == 0 && arg.value_text == "kind")
        }),
        "envelope.cmd must not taint the sibling event constructor kind argument: {:?}",
        graph.tainted_calls
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
