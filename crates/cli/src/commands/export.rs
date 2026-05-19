//! `bonsai-ninja export` — dump a scope-declared analyzed workspace as
//! one JSON document. Every analysis fact in the native export is
//! semantic-only; sections that are intentionally omitted or bounded by
//! the default export scope are marked incomplete at both the top level
//! and the section level.

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
    complete_chains: bool,
    format: ExportFormat,
) -> Result<()> {
    let cacheable_default_json = format == ExportFormat::Json && !complete_chains && !full_propagations;
    if cacheable_default_json {
        let stdout = std::io::stdout();
        let mut writer = std::io::BufWriter::with_capacity(1024 * 1024, stdout.lock());
        if bonsai_sdk::WorkspaceCache::new(root)
            .with_discovered_rulepack_root()
            .stream_default_export_cache_if_fresh(&mut writer)?
        {
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
    let export = project.export();
    let options = bonsai_sdk::NativeExportOptions {
        full_propagations,
        complete_chains,
    };
    if !cacheable_default_json {
        write_native_json_stdout(&export, options)?;
        spin.finish_and_clear();
        return Ok(());
    }
    export.write_default_json_cache_streaming(options)?;
    spin.finish_and_clear();
    stream_default_cache_or_render(&export, options)?;
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

fn stream_default_cache_or_render(
    export: &bonsai_sdk::Export<'_>,
    options: bonsai_sdk::NativeExportOptions,
) -> Result<()> {
    let stdout = std::io::stdout();
    let mut writer = std::io::BufWriter::with_capacity(1024 * 1024, stdout.lock());
    // The cache file we just wrote should be fresh, so the streaming
    // path is the expected branch. If it is not fresh, fall back to
    // rendering directly so the user always gets exactly one valid
    // JSON document on stdout.
    if !export.stream_default_json_cache_if_fresh(&mut writer)? {
        export.write_native_json(options, &mut writer)?;
        writeln!(writer)?;
    }
    writer.flush()?;
    Ok(())
}

fn write_native_json_stdout(
    export: &bonsai_sdk::Export<'_>,
    options: bonsai_sdk::NativeExportOptions,
) -> Result<()> {
    let stdout = std::io::stdout();
    let mut writer = std::io::BufWriter::with_capacity(1024 * 1024, stdout.lock());
    export.write_native_json(options, &mut writer)?;
    writeln!(writer)?;
    writer.flush()?;
    Ok(())
}
