//! `bonsai-ninja export` — dump the complete analyzed workspace as one
//! JSON document. Every file, every decl with its flow events and
//! params, every import, ref, and string, plus a derived call-graph
//! edge list. Downstream tooling (taint trackers, dashboards, IDE
//! overlays) can reconstruct any view — including the per-flow
//! source-annotated inspect output — from this document.

use anyhow::Result;
use bonsai_sdk::GraphExportFormat;
use std::io::Write;

use crate::args::ExportFormat;
use crate::commands::open_project_index_only as open_project;
use crate::progress;

/// Handler for `bonsai-ninja export`. Streams the warmed export-cache
/// when fresh, otherwise builds the requested format (native JSON,
/// NetworkX, GraphML, Cypher) and writes it to stdout.
pub(crate) fn cmd_export(
    root: &std::path::Path,
    full_propagations: bool,
    format: ExportFormat,
) -> Result<()> {
    if format == ExportFormat::Json && !full_propagations {
        let stdout = std::io::stdout();
        let mut writer = std::io::BufWriter::with_capacity(1024 * 1024, stdout.lock());
        if bonsai_sdk::WorkspaceCache::new(root).stream_default_export_cache_if_fresh(&mut writer)? {
            return Ok(());
        }
    }

    let (project, _footer) = open_project(root)?;
    if let Some(format) = graph_export_format(format) {
        let spin = progress::spinner("rendering graph");
        let rendered = project.export().graph(format)?;
        spin.finish_and_clear();
        let stdout = std::io::stdout();
        let mut writer = std::io::BufWriter::with_capacity(1024 * 1024, stdout.lock());
        writer.write_all(rendered.as_bytes())?;
        if !rendered.ends_with('\n') {
            writeln!(writer)?;
        }
        writer.flush()?;
        return Ok(());
    }

    // Native JSON export visits every file, decl, ref, import, and
    // string. On a 1 k-file workspace this is multi-second; spinner
    // signals progress while the renderer runs.
    let spin = progress::spinner("building export");
    let rendered = project
        .export()
        .native_json_string(bonsai_sdk::NativeExportOptions { full_propagations })?;
    spin.finish_and_clear();
    write_export_json(&project, &rendered, !full_propagations)?;
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

fn write_export_json(project: &bonsai_sdk::Project, out: &str, cacheable: bool) -> Result<()> {
    if cacheable {
        project.export().write_default_json_cache(out)?;
        let stdout = std::io::stdout();
        let mut writer = std::io::BufWriter::with_capacity(1024 * 1024, stdout.lock());
        // The cache file we just wrote should be fresh, so the
        // streaming path is the expected branch. If it's NOT fresh
        // (cache file disappeared between write and stream, or a
        // racing writer overwrote it with a stale copy), fall back
        // to streaming the freshly-rendered bytes directly so the
        // user always gets exactly one valid JSON document on stdout
        // — never empty output with exit 0.
        if !project.export().stream_default_json_cache_if_fresh(&mut writer)? {
            writer.write_all(out.as_bytes())?;
            writeln!(writer)?;
        }
        writer.flush()?;
        return Ok(());
    }
    let stdout = std::io::stdout();
    let mut writer = std::io::BufWriter::with_capacity(1024 * 1024, stdout.lock());
    writer.write_all(out.as_bytes())?;
    writeln!(writer)?;
    writer.flush()?;
    Ok(())
}
