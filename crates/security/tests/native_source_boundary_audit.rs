//! End-to-end source-boundary coverage for exact C and Lua SDK syntax.
//! Each positive fixture proves both rule inventory and source-to-sink IDG
//! closure; each collision fixture keeps the import present while changing
//! only the compiler-owned type/call identity.

use bonsai_security::{
    load_rulepack, run_taint_analysis, source_inventory, SecurityInventoryOptions, TaintAnalysisOptions,
};
use std::path::{Path, PathBuf};
use std::sync::Arc;

fn rules_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("security-patterns")
}

fn workspace(file: &str, source: &str) -> bonsai_workspace::Workspace {
    let ws = bonsai_workspace::Workspace::new(bonsai_adapters::all_languages_registry());
    ws.vfs().write(file.to_string(), Arc::<str>::from(source));
    ws
}

fn source_ids_and_sink_ids(file: &str, source: &str) -> (Vec<String>, Vec<String>) {
    let ws = workspace(file, source);
    let pack = load_rulepack(&rules_root()).expect("load source-controlled rulepack");
    let source_ids = source_inventory(&ws, &pack, SecurityInventoryOptions::default())
        .expect("source inventory")
        .into_iter()
        .map(|hit| hit.rule_id)
        .collect();
    let sink_ids = run_taint_analysis(&ws, &pack, TaintAnalysisOptions::default())
        .expect("taint analysis")
        .findings
        .into_iter()
        .map(|finding| finding.finding.sink.rule_id)
        .collect();
    (source_ids, sink_ids)
}

fn assert_boundary_flow(file: &str, source: &str, source_rule: &str) {
    let (sources, sinks) = source_ids_and_sink_ids(file, source);
    assert!(
        sources.iter().any(|rule| rule == source_rule),
        "missing exact source {source_rule}: {sources:?}"
    );
    assert!(
        sinks.iter().any(|rule| rule.contains("cmdi")),
        "{source_rule} must reach the command sink through the exact IDG: {sinks:?}"
    );
}

fn assert_collision_rejected(file: &str, source: &str, source_rule: &str) {
    let (sources, sinks) = source_ids_and_sink_ids(file, source);
    assert!(
        sources.iter().all(|rule| rule != source_rule),
        "collision fixture must not match {source_rule}: {sources:?}"
    );
    assert!(
        sinks.iter().all(|rule| !rule.contains("cmdi")),
        "without the exact source boundary, the local value must not become a taint finding: {sinks:?}"
    );
}

#[test]
fn c_aws_iot_typed_callback_parameter_is_a_cloud_source() {
    assert_boundary_flow(
        "mqtt.c",
        "#include \"core_mqtt.h\"\n\
         static bool on_event(MQTTContext_t *ctx, MQTTPacketInfo_t *packet,\n\
           MQTTDeserializedInfo_t *decoded, MQTTSuccessFailReasonCode_t *reason,\n\
           MQTTPropBuilder_t *send_props, MQTTPropBuilder_t *recv_props) {\n\
           system((const char *) decoded->pPublishInfo->pPayload); return true;\n\
         }\n",
        "c.cloud.aws_iot_mqtt_deserialized_event",
    );

    assert_collision_rejected(
        "local.c",
        "#include \"core_mqtt.h\"\n\
         typedef struct { const char *payload; } LocalEvent;\n\
         static void helper(LocalEvent *decoded) { system(decoded->payload); }\n",
        "c.cloud.aws_iot_mqtt_deserialized_event",
    );
}

#[test]
fn c_exact_tls_reads_remain_remote_sources_while_generic_bio_read_is_not() {
    let exact = [
        (
            "openssl.c",
            "#include <openssl/ssl.h>\n\
             void handle(SSL *ssl) { char buf[64]; SSL_read(ssl, buf, sizeof(buf)); system(buf); }\n",
            "c.input.ssl_read",
        ),
        (
            "mbedtls.c",
            "#include <mbedtls/ssl.h>\n\
             void handle(mbedtls_ssl_context *ssl) { unsigned char buf[64];\n\
               mbedtls_ssl_read(ssl, buf, sizeof(buf)); system((char *)buf); }\n",
            "c.input.mbedtls_ssl_read",
        ),
    ];
    for (file, source, rule) in exact {
        assert_boundary_flow(file, source, rule);
    }

    let (sources, sinks) = source_ids_and_sink_ids(
        "bio.c",
        "#include <openssl/bio.h>\n\
         void read_unknown_transport(BIO *bio) { char buf[64];\n\
           BIO_read(bio, buf, sizeof(buf)); system(buf); }\n",
    );
    assert!(
        sources.iter().all(|rule| rule != "c.input.bio_read"),
        "BIO_read may be backed by a file, memory, filter, or socket and must not be classified as remote by name alone: {sources:?}"
    );
    assert!(
        sinks.iter().all(|rule| !rule.contains("cmdi")),
        "transport-ambiguous BIO_read must not seed a remote taint finding: {sinks:?}"
    );
}

#[test]
fn lua_typed_cloud_queue_database_and_ipc_sources_reach_sinks() {
    let cases = [
        (
            "cloud.lua",
            "local AWS = require('resty.aws')\n\
             function entry()\n\
               local aws = AWS({ region = 'us-east-1' })\n\
               local s3 = aws:S3()\n\
               local response = s3:getObject({ Bucket = 'b', Key = 'k' })\n\
               os.execute(response.body)\n\
             end\n",
            "lua.cloud.resty_aws_s3_get_object",
        ),
        (
            "queue.lua",
            "local zmq = require('lzmq')\n\
             function entry()\n\
               local context = zmq.context()\n\
               local socket = context:socket(zmq.PULL)\n\
               local message = socket:recv()\n\
               os.execute(message)\n\
             end\n",
            "lua.queue.lzmq_socket_recv",
        ),
        (
            "database.lua",
            "local mysql = require('resty.mysql')\n\
             function entry()\n\
               local db = mysql:new()\n\
               local rows = db:query('SELECT command FROM jobs')\n\
               os.execute(rows[1].command)\n\
             end\n",
            "lua.database.resty_mysql_query_result",
        ),
        (
            "ipc.lua",
            "local lanes = require('lanes').configure()\n\
             function entry()\n\
               local mailbox = lanes.linda()\n\
               local key, value = mailbox:receive(nil, 'work')\n\
               os.execute(value)\n\
             end\n",
            "lua.ipc.lanes_linda_receive",
        ),
    ];
    for (file, source, rule) in cases {
        assert_boundary_flow(file, source, rule);
    }
}

#[test]
fn lua_same_named_local_receivers_do_not_gain_external_boundary_types() {
    let cases = [
        (
            "cloud_local.lua",
            "local AWS = require('resty.aws')\n\
             function entry(store)\n\
               local response = store:getObject({ key = 'k' })\n\
               os.execute(response.body)\n\
             end\n",
            "lua.cloud.resty_aws_s3_get_object",
        ),
        (
            "queue_local.lua",
            "local zmq = require('lzmq')\n\
             function entry(buffer)\n\
               local message = buffer:recv()\n\
               os.execute(message)\n\
             end\n",
            "lua.queue.lzmq_socket_recv",
        ),
        (
            "database_local.lua",
            "local mysql = require('resty.mysql')\n\
             function entry(builder)\n\
               local rows = builder:query('jobs')\n\
               os.execute(rows)\n\
             end\n",
            "lua.database.resty_mysql_query_result",
        ),
        (
            "ipc_local.lua",
            "local lanes = require('lanes').configure()\n\
             function entry(mailbox)\n\
               local key, value = mailbox:receive(nil, 'work')\n\
               os.execute(value)\n\
             end\n",
            "lua.ipc.lanes_linda_receive",
        ),
    ];
    for (file, source, rule) in cases {
        assert_collision_rejected(file, source, rule);
    }
}

#[test]
fn lua_http_server_aggregate_callback_types_only_the_inbound_stream() {
    assert_boundary_flow(
        "server.lua",
        "local http_server = require('http.server')\n\
         local server = http_server.listen({\n\
           onstream = function(server, stream)\n\
             local headers = stream:get_headers()\n\
             os.execute(headers:get(':path'))\n\
           end\n\
         })\n",
        "lua.source.lua_http_stream_headers",
    );

    for (file, source) in [
        (
            "outbound.lua",
            "local http_server = require('http.server')\n\
             function consume_response(stream)\n\
               local headers = stream:get_headers()\n\
               os.execute(headers:get(':status'))\n\
             end\n",
        ),
        (
            "wrong_field.lua",
            "local http_server = require('http.server')\n\
             http_server.listen({\n\
               onresponse = function(server, stream)\n\
                 local headers = stream:get_headers()\n\
                 os.execute(headers:get(':status'))\n\
               end\n\
             })\n",
        ),
    ] {
        assert_collision_rejected(file, source, "lua.source.lua_http_stream_headers");
    }
}
