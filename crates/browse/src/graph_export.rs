//! Graph database export SDK.
//!
//! The CLI `export --format networkx|graphml|cypher` command is a
//! renderer over this module. SDK callers use the same projection and
//! serializers directly, so graph database exports stay tied to the
//! indexed workspace and its prebuilt dataflow/taint sidecar instead
//! of a CLI-only JSON shape.

use crate::common::format_span;
use crate::imports::{imports, ImportsFilters};
use bonsai_common::{FuncId, Precision};
use bonsai_lang_api::{DeclKind, FlowEvent};
use bonsai_workspace::Workspace;
use serde::Serialize;
use serde_json::{Number, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::Path;

const GRAPH_EXPORT_SEMANTIC_MAX_PRECISION: Precision = Precision::Narrowed;
const GRAPH_EXPORT_INCOMPLETE_REASON: &str = "graph database formats export semantic structural edges and local flow facts; exhaustive interprocedural taint propagation records are available in native JSON with --full-propagations";

fn graph_export_analysis_incomplete_reasons() -> Vec<String> {
    vec![GRAPH_EXPORT_INCOMPLETE_REASON.to_string()]
}

/// Graph database formats exposed by the SDK and CLI.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum GraphExportFormat {
    /// NetworkX node-link JSON. Load with
    /// `networkx.node_link_graph(data, edges="links")`.
    Networkx,
    /// GraphML for graph database importers and visual tools.
    Graphml,
    /// Cypher statements suitable for Neo4j-compatible databases.
    Cypher,
}

/// One projected node in the workspace graph.
#[derive(Clone, Debug, Serialize)]
pub struct GraphNode {
    pub id: String,
    pub labels: BTreeSet<String>,
    pub properties: BTreeMap<String, Value>,
}

/// One projected edge in the workspace graph.
#[derive(Clone, Debug, Serialize)]
pub struct GraphEdge {
    pub id: String,
    pub source: String,
    pub target: String,
    pub label: String,
    pub properties: BTreeMap<String, Value>,
}

/// Stable graph projection over the indexed workspace.
#[derive(Clone, Debug, Default, Serialize)]
pub struct GraphProjection {
    pub nodes: BTreeMap<String, GraphNode>,
    pub edges: Vec<GraphEdge>,
}

impl GraphProjection {
    /// Insert (or merge) a node by id. Multiple calls with the
    /// same id accumulate labels and properties — useful when the
    /// same FuncId appears as both a `Function` and a propagation
    /// target.
    fn node<I>(&mut self, id: String, label: &str, properties: I)
    where
        I: IntoIterator<Item = (&'static str, Value)>,
    {
        let node = self.nodes.entry(id.clone()).or_insert_with(|| GraphNode {
            id,
            labels: BTreeSet::new(),
            properties: BTreeMap::new(),
        });
        node.labels.insert(label.to_string());
        for (key, value) in properties {
            // Skip nulls so consumers don't see `key: null` in
            // exported documents.
            if !value.is_null() {
                node.properties.insert(key.to_string(), value);
            }
        }
    }

    /// Append a directed edge with stable id derived from
    /// `(source, target, label, properties)`. Duplicates produce
    /// distinct edges only when their properties differ.
    fn edge<I>(&mut self, source: String, target: String, label: &str, properties: I)
    where
        I: IntoIterator<Item = (&'static str, Value)>,
    {
        let mut props = BTreeMap::new();
        for (key, value) in properties {
            if !value.is_null() {
                props.insert(key.to_string(), value);
            }
        }
        // Hash key includes serialised properties so the same
        // caller→callee pair with different precision tags gets
        // distinct edges.
        let key = format!(
            "{source}\0{target}\0{label}\0{}",
            serde_json::to_string(&props).unwrap_or_default()
        );
        self.edges.push(GraphEdge {
            id: stable_graph_id("edge", &key),
            source,
            target,
            label: label.to_string(),
            properties: props,
        });
    }
}

/// Build the graph database projection from the indexed workspace and
/// dataflow cache.
#[must_use]
pub fn graph_projection(ws: &Workspace, workspace_root: &Path) -> GraphProjection {
    let mut graph = GraphProjection::default();
    let db = ws.db();
    let global = db.global_index();
    let workspace_id = "workspace".to_string();

    graph.node(
        workspace_id.clone(),
        "Workspace",
        [
            ("name", Value::String(workspace_root.display().to_string())),
            (
                "engine_version",
                Value::String(env!("CARGO_PKG_VERSION").to_string()),
            ),
        ],
    );

    let mut file_ids: BTreeMap<String, String> = BTreeMap::new();
    let idg = db
        .idg_service()
        .unwrap_or_else(|| ws.build_and_seed_idg_service());
    for file in global.all_files() {
        let path = ws
            .vfs()
            .path(file)
            .map_or_else(|_| "<unknown>".to_string(), |p| p.display().to_string());
        let language = db
            .adapter_for(file)
            .map(|a| a.language_id().as_str().to_string())
            .unwrap_or_default();
        let file_id = stable_graph_id("file", &path);
        file_ids.insert(path.clone(), file_id.clone());
        graph.node(
            file_id.clone(),
            "File",
            [
                ("path", Value::String(path)),
                ("language", Value::String(language)),
            ],
        );
        graph.edge(workspace_id.clone(), file_id, "CONTAINS", []);
    }

    for import in imports(ws, &ImportsFilters::default()).unwrap_or_default() {
        let Some(file_id) = file_ids.get(&import.file) else {
            continue;
        };
        let module_id = stable_graph_id("module", &import.module);
        graph.node(
            module_id.clone(),
            "Module",
            [("name", Value::String(import.module.clone()))],
        );
        graph.edge(
            file_id.clone(),
            module_id,
            "IMPORTS",
            [
                ("alias", opt_string(import.alias.as_deref())),
                ("original_name", opt_string(import.original_name.as_deref())),
                ("wildcard", Value::Bool(import.is_wildcard)),
                ("line", number(import.line)),
                ("local_bindings", strings_value(&import.local_bindings)),
            ],
        );
    }

    let mut func_ids: BTreeMap<u32, String> = BTreeMap::new();
    for file in global.all_files() {
        for decl in global.decls_in(file) {
            match decl.kind {
                DeclKind::Function | DeclKind::Method | DeclKind::Constructor => {
                    let (path, line, _) = format_span(&decl.name_span, ws);
                    let func_id = format!("func_{}", decl.symbol.raw());
                    func_ids.insert(decl.symbol.raw(), func_id.clone());
                    graph.node(
                        func_id.clone(),
                        "Function",
                        [
                            ("func_id", number(decl.symbol.raw())),
                            ("name", Value::String(decl.name.clone())),
                            ("qualified_name", opt_string(decl.qualified_name.as_deref())),
                            ("file", Value::String(path.clone())),
                            ("line", number(line)),
                            ("kind", Value::String(format!("{:?}", decl.kind).to_lowercase())),
                            ("params", strings_value(&decl.params)),
                        ],
                    );
                    if let Some(file_id) = file_ids.get(&path) {
                        graph.edge(file_id.clone(), func_id, "DECLARES", []);
                    }
                }
                DeclKind::Class
                | DeclKind::Struct
                | DeclKind::Trait
                | DeclKind::Interface
                | DeclKind::Enum => {
                    let (path, line, _) = format_span(&decl.name_span, ws);
                    let methods = methods_inside_decl(global.decls_in(file), decl);
                    let class_id = stable_graph_id(
                        "class",
                        &format!("{path}\0{}\0{line}\0{:?}", decl.name, decl.kind),
                    );
                    graph.node(
                        class_id.clone(),
                        "Class",
                        [
                            ("name", Value::String(decl.name.clone())),
                            ("kind", Value::String(format!("{:?}", decl.kind).to_lowercase())),
                            ("file", Value::String(path.clone())),
                            ("line", number(line)),
                            ("method_count", number_usize(methods.len())),
                            ("methods", strings_value(&methods)),
                        ],
                    );
                    if let Some(file_id) = file_ids.get(&path) {
                        graph.edge(file_id.clone(), class_id, "DECLARES", []);
                    }
                }
                _ => {}
            }
        }
    }

    let resolved = ws.resolved_call_graph();
    for edge in resolved
        .inner()
        .edges
        .iter()
        .filter(|edge| edge.precision <= GRAPH_EXPORT_SEMANTIC_MAX_PRECISION)
    {
        let Some(source) = func_ids.get(&edge.from.raw()) else {
            continue;
        };
        let Some(target) = func_ids.get(&edge.to.raw()) else {
            continue;
        };
        graph.edge(
            source.clone(),
            target.clone(),
            "CALLS",
            [
                ("kind", Value::String(format!("{:?}", edge.kind).to_lowercase())),
                (
                    "precision",
                    Value::String(format!("{:?}", edge.precision).to_lowercase()),
                ),
            ],
        );
    }

    let summary_funcs: Vec<FuncId> = func_ids.keys().copied().map(FuncId::new).collect();
    let return_taint_by_func = idg.return_taint_param_indices_for_funcs_with_max_precision(
        &summary_funcs,
        Some(GRAPH_EXPORT_SEMANTIC_MAX_PRECISION),
    );

    for file in global.all_files() {
        for decl in global.decls_in(file) {
            if !matches!(
                decl.kind,
                DeclKind::Function | DeclKind::Method | DeclKind::Constructor
            ) {
                continue;
            }
            let Some(func_id) = func_ids.get(&decl.symbol.raw()) else {
                continue;
            };

            let mut facts: BTreeMap<&'static str, BTreeSet<String>> = BTreeMap::new();
            insert_graph_fact(&mut facts, "decl", &decl.name);
            for param in &decl.params {
                insert_graph_fact(&mut facts, "decl", param);
            }
            collect_structural_graph_facts(&decl.flow_events, &mut facts);
            for (kind, tokens) in facts {
                for token in tokens {
                    let token_id = stable_graph_id("token", &format!("{kind}\0{token}"));
                    graph.node(
                        token_id.clone(),
                        "Token",
                        [
                            ("kind", Value::String(kind.to_string())),
                            ("value", Value::String(token)),
                        ],
                    );
                    graph.edge(
                        func_id.clone(),
                        token_id,
                        "HAS_FACT",
                        [("kind", Value::String(kind.to_string()))],
                    );
                }
            }

            let summary_func = FuncId::new(decl.symbol.raw());
            let returns_taint_of = return_taint_by_func
                .get(&summary_func)
                .into_iter()
                .flatten()
                .copied()
                .take_while(|idx| (*idx as usize) < decl.params.len());
            for param_index in returns_taint_of {
                let param_index = param_index as usize;
                let param_id = stable_graph_id("param", &format!("{func_id}\0{param_index}"));
                graph.node(
                    param_id.clone(),
                    "Parameter",
                    [
                        ("function_id", Value::String(func_id.clone())),
                        ("param_index", number_usize(param_index)),
                    ],
                );
                graph.edge(
                    func_id.clone(),
                    param_id,
                    "RETURNS_TAINT_OF",
                    [("param_index", number_usize(param_index))],
                );
            }
        }
    }

    graph.node(
        workspace_id,
        "Workspace",
        [
            ("semantic_max_precision", Value::String("narrowed".to_string())),
            ("taint_propagations_complete", Value::Bool(false)),
            ("analysis_complete", Value::Bool(false)),
            (
                "analysis_incomplete_reasons",
                strings_value(&graph_export_analysis_incomplete_reasons()),
            ),
            ("taint_propagations_saturated_entries", number_usize(0)),
            (
                "taint_propagations_incomplete_reason",
                Value::String(GRAPH_EXPORT_INCOMPLETE_REASON.to_string()),
            ),
        ],
    );

    graph.edges.sort_by(|a, b| {
        a.source
            .cmp(&b.source)
            .then(a.target.cmp(&b.target))
            .then(a.label.cmp(&b.label))
            .then(a.id.cmp(&b.id))
    });
    graph
}

fn insert_graph_fact(facts: &mut BTreeMap<&'static str, BTreeSet<String>>, kind: &'static str, value: &str) {
    let value = value.trim();
    if value.is_empty() {
        return;
    }
    facts.entry(kind).or_default().insert(value.to_string());
}

fn collect_structural_graph_facts(
    events: &[FlowEvent],
    facts: &mut BTreeMap<&'static str, BTreeSet<String>>,
) {
    for event in events {
        match event {
            FlowEvent::Call {
                name, receiver, args, ..
            } => {
                insert_graph_fact(facts, "call", name);
                if let Some(receiver) = receiver {
                    insert_graph_fact(facts, "read", receiver);
                }
                for arg in args {
                    insert_graph_fact(facts, "arg", &arg.value_text);
                    if let Some(place) = arg.place.as_deref() {
                        insert_graph_fact(facts, "read", place);
                    }
                }
            }
            FlowEvent::Assign {
                target,
                source_name,
                source_names,
                source_call,
                source_call_args,
                ..
            } => {
                insert_graph_fact(facts, "write", target);
                if let Some(source_name) = source_name {
                    insert_graph_fact(facts, "read", source_name);
                }
                for source_name in source_names {
                    insert_graph_fact(facts, "read", source_name);
                }
                if let Some(source_call) = source_call {
                    insert_graph_fact(facts, "call", source_call);
                }
                for arg in source_call_args {
                    insert_graph_fact(facts, "arg", arg);
                }
            }
            FlowEvent::Return {
                value_text,
                value_name,
                ..
            } => {
                if let Some(value_name) = value_name {
                    insert_graph_fact(facts, "read", value_name);
                }
                if let Some(value_text) = value_text {
                    insert_graph_fact(facts, "arg", value_text);
                }
            }
            FlowEvent::Throw { value_name, .. } => {
                if let Some(value_name) = value_name {
                    insert_graph_fact(facts, "read", value_name);
                }
            }
            FlowEvent::Yield { value_text, .. }
            | FlowEvent::Await {
                value_name: value_text,
                ..
            } => {
                if let Some(value_text) = value_text {
                    insert_graph_fact(facts, "read", value_text);
                }
            }
            FlowEvent::Branch {
                condition,
                then_events,
                else_events,
                ..
            } => {
                if let Some(condition) = condition {
                    insert_graph_fact(facts, "arg", condition);
                }
                collect_structural_graph_facts(then_events, facts);
                collect_structural_graph_facts(else_events, facts);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                collect_structural_graph_facts(body, facts);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                catch_param,
                ..
            } => {
                if let Some(catch_param) = catch_param {
                    insert_graph_fact(facts, "write", catch_param);
                }
                collect_structural_graph_facts(body, facts);
                collect_structural_graph_facts(catch_events, facts);
                collect_structural_graph_facts(finally_events, facts);
            }
            _ => {}
        }
    }
}

/// Render a graph database export from the SDK projection.
pub fn render_graph_export(
    ws: &Workspace,
    workspace_root: &Path,
    format: GraphExportFormat,
) -> serde_json::Result<String> {
    let graph = graph_projection(ws, workspace_root);
    match format {
        GraphExportFormat::Networkx => render_networkx_json(&graph, workspace_root),
        GraphExportFormat::Graphml => Ok(render_graphml(&graph)),
        GraphExportFormat::Cypher => Ok(render_cypher(&graph)),
    }
}

/// Render NetworkX node-link JSON.
pub fn render_networkx_json(graph: &GraphProjection, workspace_root: &Path) -> serde_json::Result<String> {
    let nodes: Vec<Value> = graph
        .nodes
        .values()
        .map(|node| {
            let mut obj = serde_json::Map::new();
            obj.insert("id".to_string(), Value::String(node.id.clone()));
            let labels: Vec<String> = node.labels.iter().cloned().collect();
            obj.insert("labels".to_string(), strings_value(&labels));
            for (key, value) in &node.properties {
                obj.insert(key.clone(), value.clone());
            }
            Value::Object(obj)
        })
        .collect();
    let links: Vec<Value> = graph
        .edges
        .iter()
        .map(|edge| {
            let mut obj = serde_json::Map::new();
            obj.insert("source".to_string(), Value::String(edge.source.clone()));
            obj.insert("target".to_string(), Value::String(edge.target.clone()));
            obj.insert("key".to_string(), Value::String(edge.id.clone()));
            obj.insert("id".to_string(), Value::String(edge.id.clone()));
            obj.insert("label".to_string(), Value::String(edge.label.clone()));
            for (key, value) in &edge.properties {
                obj.insert(key.clone(), value.clone());
            }
            Value::Object(obj)
        })
        .collect();
    let out = serde_json::json!({
        "analysis_complete": false,
        "analysis_incomplete_reasons": graph_export_analysis_incomplete_reasons(),
        "directed": true,
        "multigraph": true,
        "graph": {
            "analysis_complete": false,
            "analysis_incomplete_reasons": graph_export_analysis_incomplete_reasons(),
            "name": "bonsai-ninja export",
            "engine_version": env!("CARGO_PKG_VERSION"),
            "workspace_root": workspace_root.display().to_string(),
            "format": "networkx-node-link",
            "networkx_loader": "networkx.node_link_graph(data, edges=\"links\")"
        },
        "nodes": nodes,
        "links": links
    });
    serde_json::to_string(&out)
}

/// Render GraphML.
#[must_use]
pub fn render_graphml(graph: &GraphProjection) -> String {
    let mut node_keys: BTreeSet<String> = BTreeSet::from(["label".to_string(), "labels".to_string()]);
    let mut edge_keys: BTreeSet<String> = BTreeSet::from(["label".to_string()]);
    for node in graph.nodes.values() {
        node_keys.extend(node.properties.keys().cloned());
    }
    for edge in &graph.edges {
        edge_keys.extend(edge.properties.keys().cloned());
    }

    let mut out = String::new();
    let _ = writeln!(out, r#"<?xml version="1.0" encoding="UTF-8"?>"#);
    let _ = writeln!(out, r#"<graphml xmlns="http://graphml.graphdrawing.org/xmlns">"#);
    for key in &node_keys {
        let _ = writeln!(
            out,
            r#"  <key id="n_{}" for="node" attr.name="{}" attr.type="string"/>"#,
            xml_attr(key),
            xml_attr(key)
        );
    }
    for key in &edge_keys {
        let _ = writeln!(
            out,
            r#"  <key id="e_{}" for="edge" attr.name="{}" attr.type="string"/>"#,
            xml_attr(key),
            xml_attr(key)
        );
    }
    let _ = writeln!(out, r#"  <graph id="bonsai" edgedefault="directed">"#);
    for node in graph.nodes.values() {
        let _ = writeln!(out, r#"    <node id="{}">"#, xml_attr(&node.id));
        let labels: Vec<String> = node.labels.iter().cloned().collect();
        write_graphml_data(&mut out, "n_label", labels.first().map_or("", String::as_str));
        write_graphml_data(&mut out, "n_labels", &labels.join(","));
        for (key, value) in &node.properties {
            write_graphml_data(&mut out, &format!("n_{key}"), &graph_value_string(value));
        }
        let _ = writeln!(out, "    </node>");
    }
    for edge in &graph.edges {
        let _ = writeln!(
            out,
            r#"    <edge id="{}" source="{}" target="{}">"#,
            xml_attr(&edge.id),
            xml_attr(&edge.source),
            xml_attr(&edge.target)
        );
        write_graphml_data(&mut out, "e_label", &edge.label);
        for (key, value) in &edge.properties {
            write_graphml_data(&mut out, &format!("e_{key}"), &graph_value_string(value));
        }
        let _ = writeln!(out, "    </edge>");
    }
    let _ = writeln!(out, "  </graph>");
    let _ = writeln!(out, "</graphml>");
    out
}

/// Render Cypher statements for Neo4j-compatible import.
#[must_use]
pub fn render_cypher(graph: &GraphProjection) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "CREATE CONSTRAINT bonsai_node_id IF NOT EXISTS FOR (n:BonsaiNode) REQUIRE n.id IS UNIQUE;"
    );
    for node in graph.nodes.values() {
        let labels = node
            .labels
            .iter()
            .map(|label| cypher_label(label))
            .collect::<Vec<_>>()
            .join(":");
        let labels = if labels.is_empty() {
            "BonsaiNode".to_string()
        } else {
            format!("BonsaiNode:{labels}")
        };
        let _ = writeln!(
            out,
            "MERGE (n:{labels} {{id: {}}}) SET n += {};",
            cypher_value(&Value::String(node.id.clone())),
            cypher_map(&node.properties)
        );
    }
    for edge in &graph.edges {
        let mut properties = edge.properties.clone();
        properties.insert("id".to_string(), Value::String(edge.id.clone()));
        let _ = writeln!(
            out,
            "MATCH (a:BonsaiNode {{id: {}}}), (b:BonsaiNode {{id: {}}}) MERGE (a)-[r:{} {{id: {}}}]->(b) SET r += {};",
            cypher_value(&Value::String(edge.source.clone())),
            cypher_value(&Value::String(edge.target.clone())),
            cypher_label(&edge.label),
            cypher_value(&Value::String(edge.id.clone())),
            cypher_map(&properties)
        );
    }
    out
}

/// Collect the names of every callable decl whose span sits
/// inside `container`'s span — used to attach a `methods` list to
/// each class node.
fn methods_inside_decl(decls: &[bonsai_lang_api::Decl], container: &bonsai_lang_api::Decl) -> Vec<String> {
    decls
        .iter()
        .filter(|decl| {
            matches!(
                decl.kind,
                DeclKind::Method | DeclKind::Constructor | DeclKind::Function
            )
        })
        .filter(|decl| {
            container.span.file == decl.span.file
                && container.span.start <= decl.span.start
                && decl.span.end <= container.span.end
        })
        .map(|decl| decl.name.clone())
        .collect()
}

/// Build a stable graph id of the form `<prefix>_<16-hex>` over
/// the FNV-1a-64 hash of `key`. Stable across runs — the same
/// `(prefix, key)` always produces the same id, so external
/// importers can match nodes between sequential exports.
fn stable_graph_id(prefix: &str, key: &str) -> String {
    format!("{prefix}_{:016x}", fnv1a64(key.as_bytes()))
}

/// FNV-1a-64. Inlined here to avoid pulling another hash crate.
fn fnv1a64(bytes: &[u8]) -> u64 {
    const FNV_OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
    const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;
    let mut digest = FNV_OFFSET_BASIS;
    for &byte in bytes {
        digest ^= u64::from(byte);
        digest = digest.wrapping_mul(FNV_PRIME);
    }
    digest
}

fn number(value: u32) -> Value {
    Value::Number(Number::from(value))
}

fn number_usize(value: usize) -> Value {
    Value::Number(Number::from(u64::try_from(value).unwrap_or(u64::MAX)))
}

fn opt_string(value: Option<&str>) -> Value {
    value.map_or(Value::Null, |value| Value::String(value.to_string()))
}

fn strings_value(values: &[String]) -> Value {
    Value::Array(values.iter().cloned().map(Value::String).collect())
}

fn graph_value_string(value: &Value) -> String {
    match value {
        Value::Null => String::new(),
        Value::Bool(value) => value.to_string(),
        Value::Number(value) => value.to_string(),
        Value::String(value) => value.clone(),
        Value::Array(_) | Value::Object(_) => serde_json::to_string(value).unwrap_or_default(),
    }
}

fn write_graphml_data(out: &mut String, key: &str, value: &str) {
    let _ = writeln!(
        out,
        r#"      <data key="{}">{}</data>"#,
        xml_attr(key),
        xml_text(value)
    );
}

fn xml_attr(value: &str) -> String {
    xml_text(value)
}

fn xml_text(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

/// Cypher label: uppercase ASCII alphanumerics + underscore.
/// Anything else becomes `_`. Labels can't start with a digit, so
/// we prepend `_` when needed.
fn cypher_label(value: &str) -> String {
    let mut out = String::new();
    for ch in value.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_uppercase());
        } else {
            out.push('_');
        }
    }
    if out.is_empty() || out.as_bytes().first().is_some_and(u8::is_ascii_digit) {
        out.insert(0, '_');
    }
    out
}

fn cypher_map(properties: &BTreeMap<String, Value>) -> String {
    let entries = properties
        .iter()
        .map(|(key, value)| format!("{}: {}", cypher_property_key(key), cypher_value(value)))
        .collect::<Vec<_>>()
        .join(", ");
    format!("{{{entries}}}")
}

fn cypher_property_key(key: &str) -> String {
    let valid = key
        .chars()
        .enumerate()
        .all(|(idx, ch)| ch == '_' || (ch.is_ascii_alphanumeric() && (idx > 0 || !ch.is_ascii_digit())));
    if valid {
        key.to_string()
    } else {
        format!("`{}`", key.replace('`', "``"))
    }
}

fn cypher_value(value: &Value) -> String {
    match value {
        Value::Null => "null".to_string(),
        Value::Bool(value) => value.to_string(),
        Value::Number(value) => value.to_string(),
        Value::String(value) => format!("'{}'", value.replace('\\', "\\\\").replace('\'', "\\'")),
        Value::Array(values) => format!(
            "[{}]",
            values.iter().map(cypher_value).collect::<Vec<_>>().join(", ")
        ),
        Value::Object(_) => cypher_value(&Value::String(serde_json::to_string(value).unwrap_or_default())),
    }
}

#[cfg(test)]
#[path = "graph_export_tests.rs"]
mod tests;
