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
    assert!(networkx.contains("\"semantic_max_precision\":\"narrowed\""));
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
