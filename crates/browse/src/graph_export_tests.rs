use super::*;
use bonsai_lang_api::LanguageRegistry;
use std::sync::Arc;

#[test]
fn renders_networkx_graphml_and_cypher_from_sdk_projection() {
    let registry = Arc::new(LanguageRegistry::new());
    let ws = Workspace::new(registry);
    let root = Path::new("fixture");

    let networkx = render_graph_export(&ws, root, GraphExportFormat::Networkx).unwrap();
    assert!(networkx.contains("\"networkx-node-link\""));
    assert!(networkx.contains("\"nodes\""));
    assert!(networkx.contains("\"links\""));
    assert!(networkx.contains("\"analysis_complete\":false"));
    assert!(networkx.contains("\"analysis_incomplete_reasons\""));
    assert!(networkx.contains("\"taint_propagations_complete\":false"));
    assert!(networkx.contains("\"taint_propagations_incomplete_reason\""));

    let graphml = render_graph_export(&ws, root, GraphExportFormat::Graphml).unwrap();
    assert!(graphml.starts_with("<?xml"));
    assert!(graphml.contains("<graphml"));
    assert!(graphml.contains("analysis_complete"));
    assert!(graphml.contains("analysis_incomplete_reasons"));
    assert!(graphml.contains("taint_propagations_complete"));

    let cypher = render_graph_export(&ws, root, GraphExportFormat::Cypher).unwrap();
    assert!(cypher.contains("CREATE CONSTRAINT bonsai_node_id"));
    assert!(cypher.contains("MERGE (n:BonsaiNode:WORKSPACE"));
    assert!(cypher.contains("analysis_complete"));
    assert!(cypher.contains("analysis_incomplete_reasons"));
    assert!(cypher.contains("taint_propagations_complete"));
}

#[test]
fn graph_projection_composes_resolved_return_summaries() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(
        dir.path().join("app.py"),
        r#"
def identity(value):
    return value

def wrapper(user):
    return identity(user)
"#,
    )
    .expect("write fixture");
    let ws = Workspace::index(dir.path(), bonsai_adapters::all_languages_registry()).expect("index fixture");
    let graph = graph_projection(&ws, dir.path());
    let wrapper_id = graph
        .nodes
        .values()
        .find(|node| node.properties.get("name") == Some(&serde_json::json!("wrapper")))
        .map(|node| node.id.clone())
        .expect("wrapper graph node");

    assert!(graph.edges.iter().any(|edge| {
        edge.source == wrapper_id
            && edge.label == "RETURNS_TAINT_OF"
            && edge.properties.get("param_index") == Some(&serde_json::json!(0))
    }));
}

fn graph_fixture(source: &str, filename: &str) -> (tempfile::TempDir, Workspace) {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join(filename), source).expect("write fixture");
    let ws = Workspace::index(dir.path(), bonsai_adapters::all_languages_registry()).expect("index fixture");
    (dir, ws)
}

#[test]
fn graph_ids_do_not_merge_unrelated_workspaces() {
    let source = "import os\ndef identity(value):\n    return value\n";
    let (left_root, left) = graph_fixture(source, "app.py");
    let (right_root, right) = graph_fixture(source, "app.py");
    let first = graph_projection(&left, left_root.path());
    let second = graph_projection(&right, right_root.path());
    assert!(
        first.nodes.keys().all(|key| !second.nodes.contains_key(key)),
        "separate project imports must never overwrite each other's nodes"
    );
    let replay = graph_projection(&left, left_root.path());
    assert_eq!(
        first.nodes.keys().collect::<Vec<_>>(),
        replay.nodes.keys().collect::<Vec<_>>()
    );
}

#[test]
fn graph_serializers_escape_source_text_and_cypher_keys() {
    let mut graph = GraphProjection::default();
    graph.node(
        "one".to_string(),
        "Function",
        [
            (
                "name",
                Value::String("quote' slash\\ newline\ncarriage\rtab\t<&>\"".to_string()),
            ),
            ("", Value::String("empty property key".to_string())),
        ],
    );
    let json: Value =
        serde_json::from_str(&render_networkx_json(&graph, Path::new("fixture")).unwrap()).unwrap();
    assert_eq!(json["nodes"][0]["name"], graph.nodes["one"].properties["name"]);
    let xml = render_graphml(&graph).expect("GraphML");
    assert!(xml.contains("&lt;&amp;&gt;&quot;"));
    assert!(xml.contains("quote&apos;"));
    assert!(xml.contains("newline&#10;carriage&#13;tab&#9;"));
    let document = roxmltree::Document::parse(&xml).expect("parse exported XML");
    let decoded = document
        .descendants()
        .find(|node| node.has_tag_name("data") && node.attribute("key") == Some("n_name"))
        .and_then(|node| node.text())
        .unwrap();
    assert_eq!(decoded, graph.nodes["one"].properties["name"].as_str().unwrap());
    let cypher = render_cypher(&graph);
    assert!(cypher.contains("quote\\' slash\\\\ newline\\ncarriage\\rtab\\t"));
    assert!(cypher.contains("``: 'empty property key'"));
    assert_eq!(
        cypher.lines().count(),
        2,
        "source newlines must not split statements"
    );
}

#[test]
fn graphml_rejects_unrepresentable_characters_without_rewriting_facts() {
    for invalid in ['\0', '\u{8}', '\u{b}', '\u{c}', '\u{1f}', '\u{fffe}', '\u{ffff}'] {
        let mut graph = GraphProjection::default();
        graph.node(
            "one".into(),
            "Function",
            [("name", Value::String(format!("left{invalid}right")))],
        );
        let error = render_graphml(&graph).expect_err("XML 1.0 cannot represent this value");
        assert!(error.to_string().contains("use native JSON or NetworkX JSON"));
        let json = render_networkx_json(&graph, Path::new("fixture")).unwrap();
        assert_eq!(
            serde_json::from_str::<Value>(&json).unwrap()["nodes"][0]["name"],
            graph.nodes["one"].properties["name"]
        );
    }
}

#[test]
fn graph_classes_keep_distinct_same_line_declaration_identities() {
    let (dir, ws) = graph_fixture(
        "function alpha() { class Shared { first() {} } return Shared; } function beta() { class Shared { second() {} } return Shared; }\n",
        "app.js",
    );
    let graph = graph_projection(&ws, dir.path());
    let classes: Vec<_> = graph
        .nodes
        .values()
        .filter(|node| node.labels.contains("Class"))
        .collect();
    assert_eq!(classes.len(), 2, "same-line classes must not merge: {classes:#?}");
    assert_ne!(classes[0].id, classes[1].id);
    assert_ne!(
        classes[0].properties.get("column"),
        classes[1].properties.get("column")
    );
    assert!(classes
        .iter()
        .any(|node| node.properties.get("methods") == Some(&serde_json::json!(["first"]))));
    assert!(classes
        .iter()
        .any(|node| node.properties.get("methods") == Some(&serde_json::json!(["second"]))));
}

#[test]
fn graph_class_methods_follow_exact_parent_ownership() {
    let (dir, ws) = graph_fixture(
        "class Outer:\n    class Inner:\n        def child(self):\n            pass\n    def parent(self):\n        def local():\n            pass\n        local()\n",
        "app.py",
    );
    let graph = graph_projection(&ws, dir.path());
    for (name, methods) in [
        ("Outer", serde_json::json!(["parent"])),
        ("Inner", serde_json::json!(["child"])),
    ] {
        let class = graph
            .nodes
            .values()
            .find(|node| {
                node.labels.contains("Class") && node.properties.get("name") == Some(&serde_json::json!(name))
            })
            .expect("class node");
        assert_eq!(
            class.properties.get("methods"),
            Some(&methods),
            "{name} owns only its direct methods"
        );
    }
}

#[test]
fn graph_file_keys_preserve_declaration_and_exact_import_edges() {
    let (dir, ws) = graph_fixture(
        "import os; import os\n\nclass Box:\n    def value(self):\n        return os.getcwd()\n",
        "app.py",
    );
    let graph = graph_projection(&ws, dir.path());
    let file = graph
        .nodes
        .values()
        .find(|node| node.labels.contains("File"))
        .expect("file node");
    assert_eq!(file.properties.get("path"), Some(&serde_json::json!("app.py")));
    for node in graph
        .nodes
        .values()
        .filter(|node| node.labels.contains("Function") || node.labels.contains("Class"))
    {
        assert_eq!(
            graph
                .edges
                .iter()
                .filter(|edge| edge.source == file.id && edge.target == node.id && edge.label == "DECLARES")
                .count(),
            1,
            "missing ownership for {}",
            node.id
        );
    }
    let imports: Vec<_> = graph
        .edges
        .iter()
        .filter(|edge| edge.label == "IMPORTS")
        .collect();
    assert_eq!(imports.len(), 2, "each source import retains its own edge");
    assert_ne!(imports[0].id, imports[1].id);
    assert_ne!(
        imports[0].properties.get("column"),
        imports[1].properties.get("column")
    );
    let edge_ids: BTreeSet<_> = graph.edges.iter().map(|edge| &edge.id).collect();
    assert_eq!(
        edge_ids.len(),
        graph.edges.len(),
        "GraphML edge IDs must be unique"
    );
    for edge in &graph.edges {
        assert!(graph.nodes.contains_key(&edge.source) && graph.nodes.contains_key(&edge.target));
    }
}

#[test]
fn graph_facts_include_typed_aggregate_assignments() {
    let events = vec![FlowEvent::AggregateAssign {
        span: bonsai_common::Span::new(bonsai_common::FileId::new(0), 0, 12),
        target: "box".to_string(),
        type_name: None,
        value_flow: bonsai_lang_api::ExpressionFlow {
            source_names: vec!["input".to_string()],
            ..Default::default()
        },
    }];
    let mut facts = BTreeMap::new();
    collect_structural_graph_facts(&events, &mut facts);
    assert!(facts.get("write").is_some_and(|names| names.contains("box")));
    assert!(facts.get("read").is_some_and(|names| names.contains("input")));
}

#[test]
fn graph_fact_walk_handles_deep_structured_regions_on_the_heap() {
    let span = bonsai_common::Span::new(bonsai_common::FileId::new(0), 0, 12);
    let mut events = vec![FlowEvent::AggregateAssign {
        span,
        target: "output".to_string(),
        type_name: None,
        value_flow: ExpressionFlow::from_place("input"),
    }];
    for _ in 0..10_000 {
        events = vec![FlowEvent::Using { span, body: events }];
    }
    let mut facts = BTreeMap::new();
    collect_structural_graph_facts(&events, &mut facts);
    let found = facts.get("read").is_some_and(|names| names.contains("input"));
    let mut pending = events;
    while let Some(event) = pending.pop() {
        if let FlowEvent::Using { body, .. } = event {
            pending.extend(body);
        }
    }
    assert!(found);
}
