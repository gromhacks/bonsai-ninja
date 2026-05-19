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
