use bonsai_db::AnalyzerDb;
use bonsai_lang_api::{CallKind, FlowEvent, LanguageRegistry};
use bonsai_vfs::Vfs;
use std::sync::Arc;

fn db_with(source: &str) -> AnalyzerDb {
    let vfs = Arc::new(Vfs::new());
    vfs.write("boundary.lua".to_string(), Arc::<str>::from(source));
    let registry = Arc::new(LanguageRegistry::new());
    registry.register(Arc::new(bonsai_lang_lua::LuaAdapter::new()));
    let db = AnalyzerDb::new(vfs, registry);
    for file in db.vfs().all_files() {
        let _ = db.decl_index(file);
    }
    db
}

fn entry(db: &AnalyzerDb) -> bonsai_lang_api::Decl {
    let global = db.global_index();
    global
        .find_by_name("entry")
        .iter()
        .find_map(|symbol| global.decl_of(*symbol).cloned())
        .expect("entry declaration")
}

#[test]
fn constructor_and_colon_call_chains_keep_exact_receivers() {
    let db = db_with(
        "function entry(AWS, zmq, mysql)\n\
           local aws = AWS({ region = 'us-east-1' })\n\
           local s3 = aws:S3()\n\
           local response = s3:getObject({ Bucket = 'b', Key = 'k' })\n\
           local context = zmq.context()\n\
           local socket = context:socket(zmq.PULL)\n\
           local message = socket:recv()\n\
           local db = mysql:new()\n\
           local rows = db:query('SELECT name FROM users')\n\
         end\n",
    );
    let entry = entry(&db);
    let file = db.vfs().all_files().into_iter().next().expect("Lua fixture file");
    let index = db.decl_index(file).expect("Lua declaration index");
    let factory_assignment = index
        .assignment_values
        .iter()
        .find(|fact| fact.target.as_deref() == Some("db"))
        .expect("mysql:new assignment fact");
    assert_eq!(factory_assignment.direct_call_name.as_deref(), Some("mysql:new"));
    assert_eq!(factory_assignment.direct_call_receiver.as_deref(), Some("mysql"));
    for (name, receiver, kind) in [
        ("AWS", None, CallKind::Function),
        ("aws.S3", Some("aws"), CallKind::Method),
        ("s3.getObject", Some("s3"), CallKind::Method),
        ("zmq.context", None, CallKind::Function),
        ("context.socket", Some("context"), CallKind::Method),
        ("socket.recv", Some("socket"), CallKind::Method),
        ("mysql.new", Some("mysql"), CallKind::Method),
        ("db.query", Some("db"), CallKind::Method),
    ] {
        assert!(
            entry.flow_events.iter().any(|event| matches!(
                event,
                FlowEvent::Call {
                    name: actual,
                    receiver: actual_receiver,
                    call_kind,
                    ..
                } if actual == name
                    && actual_receiver.as_deref() == receiver
                    && *call_kind == kind
            )),
            "missing exact Lua call fact {name} / {receiver:?} / {kind:?}: {:#?}",
            entry.flow_events
        );
    }
}

#[test]
fn method_callback_argument_keeps_parameter_order_and_scope() {
    let db = db_with(
        "function entry(uv)\n\
           local pipe = uv.new_pipe(false)\n\
           pipe:read_start(function(err, chunk)\n\
             if chunk then sink(chunk) end\n\
           end)\n\
         end\n",
    );
    let file = db.vfs().all_files()[0];
    let index = db.decl_index(file).expect("Lua declaration index");
    let entry = index
        .defs
        .iter()
        .find(|decl| decl.name == "entry")
        .expect("entry declaration");
    assert!(
        entry
            .flow_events
            .iter()
            .all(|event| !matches!(event, FlowEvent::Branch { .. })),
        "the callback branch belongs to the callback declaration, not entry: {:#?}",
        entry.flow_events
    );

    let callback_fact = index
        .call_argument_values
        .iter()
        .find(|fact| fact.inline_callback_params == ["err", "chunk"])
        .expect("callback argument fact");
    assert_eq!(callback_fact.argument_index, 0);
    let callback_span = callback_fact
        .inline_callback_span
        .expect("exact callback declaration span");
    let callback_decl = index
        .defs
        .iter()
        .find(|decl| decl.span == callback_span)
        .expect("callback declaration");
    assert_eq!(callback_decl.params, ["err", "chunk"]);
    assert!(callback_decl.flow_events.iter().any(|event| matches!(
        event,
        FlowEvent::Branch { then_events, .. }
            if then_events.iter().any(|nested| matches!(
                nested,
                FlowEvent::Call { name, args, .. }
                    if name == "sink" && args.len() == 1 && args[0].value_text == "chunk"
            ))
    )));
}

#[test]
fn aggregate_field_callback_keeps_exact_path_and_parameter_order() {
    let db = db_with(
        "function entry(http_server)\n\
           http_server.listen({\n\
             host = '127.0.0.1',\n\
             onstream = function(server, stream)\n\
               local headers = stream:get_headers()\n\
               sink(headers)\n\
             end\n\
           })\n\
         end\n",
    );
    let file = db.vfs().all_files()[0];
    let index = db.decl_index(file).expect("Lua declaration index");
    let callback = index
        .call_argument_values
        .iter()
        .flat_map(|argument| {
            argument
                .inline_callback_fields
                .iter()
                .map(move |callback| (argument.argument_index, callback))
        })
        .find(|(_, callback)| callback.path == ["onstream"])
        .expect("static onstream callback field");
    assert_eq!(callback.0, 0);
    assert_eq!(callback.1.params, ["server", "stream"]);
    let callback_decl = index
        .defs
        .iter()
        .find(|decl| decl.span == callback.1.callback_span)
        .expect("aggregate callback declaration");
    assert!(
        callback_decl.flow_events.iter().any(|event| matches!(
            event,
            FlowEvent::Call { name, .. } if name == "stream.get_headers"
        )),
        "aggregate callback body must lower into its exact callable owner: {:#?}",
        callback_decl.flow_events
    );

    let header = bonsai_lang_api::CompilerSyntaxHeader::from_decl_index(&index);
    assert!(header.callback_arguments.iter().any(|callback| {
        callback.call_name == "http_server.listen"
            && callback.argument_index == 0
            && callback.field_path == ["onstream"]
            && callback.params == ["server", "stream"]
    }));
}

#[test]
fn duplicate_aggregate_callback_field_fails_closed() {
    let db = db_with(
        "function entry(http_server)\n\
           http_server.listen({\n\
             onstream = function(server, stream) sink(stream) end,\n\
             onstream = function(server, response) sink(response) end\n\
           })\n\
         end\n",
    );
    let file = db.vfs().all_files()[0];
    let index = db.decl_index(file).expect("Lua declaration index");
    assert!(
        index
            .call_argument_values
            .iter()
            .all(|argument| argument.inline_callback_fields.is_empty()),
        "a duplicate configuration key can overwrite the callback and must not produce exact field evidence"
    );
}
