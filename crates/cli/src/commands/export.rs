//! `bonsai-ninja export` — dump a scope-declared analyzed workspace as
//! one JSON document. Every analysis fact in the native export is
//! semantic-only; sections intentionally omitted by the default export
//! scope are marked incomplete at both the top level and the section level.

use anyhow::Result;
use bonsai_sdk::GraphExportFormat;

use crate::args::ExportFormat;
use crate::commands::open_project_with_options;
use crate::output;
use crate::progress;

/// Handler for `bonsai-ninja export`. Reuses an explicitly warmed default
/// export cache when fresh; otherwise builds the requested format (native
/// JSON, NetworkX, GraphML, Cypher) directly into the configured output sink.
/// A one-shot export never creates a hidden multi-gigabyte cache and then
/// copies it to the same requested destination.
pub(crate) fn cmd_export(
    root: &std::path::Path,
    full_propagations: bool,
    compiled_propagations: bool,
    format: ExportFormat,
) -> Result<()> {
    let cacheable_default_json = format == ExportFormat::Json && !full_propagations && !compiled_propagations;
    if cacheable_default_json {
        let stage = progress::ScopedSpinner::new("checking export cache");
        let cache_hit = output::with_writer(|writer| {
            bonsai_sdk::WorkspaceCache::new(root)
                .with_discovered_rulepack_root()
                .stream_default_export_cache_if_fresh(writer)
        })?;
        stage.finish();
        if cache_hit {
            return Ok(());
        }
    }

    // Export consumes callgraph sections first and IDG sections second. Do
    // not eagerly decode both multi-gigabyte compiler artifacts during open;
    // the renderer restores the exact IDG after releasing the callgraph.
    let mut open_options = bonsai_sdk::OpenOptions::query_only();
    open_options.load_dataflow_sidecar = false;
    open_options.load_value_flow_sidecar = false;
    open_options.load_idg_sidecar = false;
    let (project, _footer) = open_project_with_options(root, open_options)?;
    if let Some(format) = graph_export_format(format) {
        let spin = progress::ScopedSpinner::new("rendering graph export");
        let rendered = project.export().graph(format)?;
        spin.finish();
        output::with_writer(|writer| {
            writer.write_all(rendered.as_bytes())?;
            if !rendered.ends_with('\n') {
                writeln!(writer)?;
            }
            Ok(())
        })?;
        return Ok(());
    }

    // Native JSON export visits every file, decl, ref, import, and
    // string. On a 1 k-file workspace this is multi-second; spinner
    // signals progress while the renderer runs.
    let spin = progress::ScopedSpinner::new("building native export");
    let export = project.export();
    let options = bonsai_sdk::NativeExportOptions {
        full_propagations,
        compiled_propagations,
    };
    write_native_json(&export, options)?;
    spin.finish();
    Ok(())
}

pub(crate) fn warm_export_cache_for_project(project: &bonsai_sdk::Project) -> Result<()> {
    project.export().warm_default_json_cache()
}

fn graph_export_format(format: ExportFormat) -> Option<GraphExportFormat> {
    match format {
        ExportFormat::Json => None,
        ExportFormat::Networkx => Some(GraphExportFormat::Networkx),
        ExportFormat::Graphml => Some(GraphExportFormat::Graphml),
        ExportFormat::Cypher => Some(GraphExportFormat::Cypher),
    }
}

fn write_native_json(
    export: &bonsai_sdk::Export<'_>,
    options: bonsai_sdk::NativeExportOptions,
) -> Result<()> {
    output::with_writer(|writer| {
        export.write_native_json(options, writer)?;
        writeln!(writer)?;
        Ok(())
    })
}
