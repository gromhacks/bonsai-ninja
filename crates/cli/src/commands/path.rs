//! `bonsai-ninja path` — ranked structural call paths between two functions.

use anyhow::Result;
use bonsai_sdk::{PathFilters, PathOutcome, PathRow};
use comfy_table::Cell;

use crate::args::BrowseFormat;
use crate::footer::render_paging_footer;
use crate::page_cache;
use crate::paging;
use crate::progress;
use crate::{cli_println, ui};

use super::{
    open_project_index_only as open_project, page_info_to_json, paged_json_incomplete_reasons, short_file,
};

pub(crate) struct PathCommandOptions<'a> {
    pub(crate) from: &'a str,
    pub(crate) to: &'a str,
    pub(crate) regex: bool,
    pub(crate) max_paths: usize,
    pub(crate) max_depth: usize,
    pub(crate) max_probes: usize,
    pub(crate) paging_cfg: paging::PagingConfig,
    pub(crate) format: BrowseFormat,
}

pub(crate) fn cmd_path(root: &std::path::Path, options: PathCommandOptions<'_>) -> Result<()> {
    let (project, _footer) = open_project(root)?;
    let filters = PathFilters {
        from: options.from,
        to: options.to,
        regex: options.regex,
        max_paths: options.max_paths,
        max_depth: options.max_depth,
        max_probes: options.max_probes,
    };
    let stage = progress::ScopedSpinner::new("enumerating semantic paths");
    let outcome = project.browse().paths(filters)?;
    stage.finish();
    let max_paths_s = options.max_paths.to_string();
    let max_depth_s = options.max_depth.to_string();
    let max_probes_s = options.max_probes.to_string();
    let filters_hash = paging::hash_filters(&[
        ("from", options.from),
        ("to", options.to),
        ("regex", if options.regex { "1" } else { "0" }),
        ("max_paths", max_paths_s.as_str()),
        ("max_depth", max_depth_s.as_str()),
        ("max_probes", max_probes_s.as_str()),
    ]);
    match options.format {
        BrowseFormat::Json | BrowseFormat::Sarif => {
            emit_path_json(root, &outcome, &options.paging_cfg, filters_hash)
        }
        BrowseFormat::Text => page_cache::emit_paged_text(
            root,
            &outcome.paths,
            &options.paging_cfg,
            "path",
            filters_hash,
            path_cost,
            |paths, info, _cfg| {
                render_path_text(&outcome, paths);
                render_paging_footer(info, "bonsai-ninja path <workspace> --from <A> --to <B>");
                Ok(())
            },
        ),
    }
}

fn emit_path_json(
    root: &std::path::Path,
    outcome: &PathOutcome,
    paging_cfg: &paging::PagingConfig,
    filters_hash: u64,
) -> Result<()> {
    if !paging_cfg.json_wrapped() {
        cli_println!("{}", serde_json::to_string_pretty(outcome)?);
        return Ok(());
    }
    let force_wrapper = paging_cfg.context.is_some()
        || !matches!(paging_cfg.page, paging::PageArg::First)
        || crate::filter::active().is_active();
    page_cache::emit_paged_text(
        root,
        &outcome.paths,
        paging_cfg,
        "path",
        filters_hash,
        path_cost,
        |paths, info, _cfg| {
            if !force_wrapper && info.page_number == 1 && info.is_last {
                cli_println!("{}", serde_json::to_string_pretty(outcome)?);
                return Ok(());
            }
            let mut reasons = outcome.analysis_incomplete_reasons.clone();
            reasons.extend(paged_json_incomplete_reasons("path", info));
            reasons.sort();
            reasons.dedup();
            let wrapped = serde_json::json!({
                "from": outcome.from,
                "to": outcome.to,
                "backends": outcome.backends,
                "idg_available": outcome.idg_available,
                "idg_semantic_edges": outcome.idg_semantic_edges,
                "from_matches": outcome.from_matches,
                "to_matches": outcome.to_matches,
                "max_paths": outcome.max_paths,
                "max_depth": outcome.max_depth,
                "max_probes": outcome.max_probes,
                "path_count": outcome.path_count,
                "analysis_complete": reasons.is_empty(),
                "analysis_incomplete_reasons": reasons,
                "paths": paths,
                "page": page_info_to_json(info),
            });
            cli_println!("{}", serde_json::to_string_pretty(&wrapped)?);
            Ok(())
        },
    )
}

fn render_path_text(outcome: &PathOutcome, paths: &[PathRow]) {
    let u = ui();
    cli_println!();
    cli_println!(
        "{}",
        u.heading(&format!("▸ path {} → {}", outcome.from, outcome.to))
    );
    cli_println!(
        "  {} {}    {} {}    {} {}    {} {}",
        u.label("sources"),
        u.name(&outcome.from_matches.to_string()),
        u.label("targets"),
        u.name(&outcome.to_matches.to_string()),
        u.label("paths"),
        u.name(&outcome.path_count.to_string()),
        u.label("status"),
        analysis_status(outcome.analysis_complete)
    );
    if !outcome.backends.is_empty() {
        cli_println!(
            "  {} {}",
            u.label("backends"),
            u.name(&outcome.backends.join(", "))
        );
    }
    let idg_status = if outcome.idg_available {
        u.name("available")
    } else {
        u.warn("unavailable")
    };
    cli_println!(
        "  {} {} · {}",
        u.label("IDG"),
        idg_status,
        counted(outcome.idg_semantic_edges, "semantic edge", "semantic edges")
    );
    if !outcome.analysis_incomplete_reasons.is_empty() {
        for line in
            u.wrapped_warn_labeled_lines("incomplete", &outcome.analysis_incomplete_reasons.join("; "))
        {
            cli_println!("{line}");
        }
    }
    if paths.is_empty() {
        cli_println!();
        cli_println!("{}", u.dim("(no semantic path matched)"));
        return;
    }

    for path in paths {
        cli_println!();
        cli_println!(
            "{} {}  {}",
            u.label("PATH"),
            u.name(&path.path_id),
            u.dim(&format!("[{} hop(s), precision {}]", path.hops, path.precision))
        );
        let mut table = u.table(&["#", "function", "location", "via call"]);
        for (idx, func) in path.functions.iter().enumerate() {
            let via = path.edges.get(idx).map_or_else(
                || String::from("-"),
                |edge| {
                    format!(
                        "{} at {}:{}",
                        edge.call_text,
                        short_file(&edge.call_file),
                        edge.call_line
                    )
                },
            );
            table.add_row(vec![
                Cell::new(u.dim(&(idx + 1).to_string())),
                Cell::new(u.name(&func.name)),
                Cell::new(u.path(&format!("{}:{}", short_file(&func.file), func.line))),
                Cell::new(u.dim(&via)),
            ]);
        }
        cli_println!("{table}");
        if let Some(call) = &path.terminal_call {
            cli_println!(
                "  {} {} at {}:{}:{} inside {}",
                u.label("terminal call"),
                u.name(&call.name),
                u.path(&short_file(&call.file)),
                call.line,
                call.column,
                u.name(&call.enclosing_function)
            );
        }
    }
}

fn path_cost(path: &PathRow) -> u64 {
    let funcs = path
        .functions
        .iter()
        .map(|func| func.name.len() + func.file.len() + 24)
        .sum::<usize>();
    let edges = path
        .edges
        .iter()
        .map(|edge| edge.call_text.len() + edge.call_file.len() + 32)
        .sum::<usize>();
    (funcs + edges + 128) as u64 + paging::TABLE_ROW_CHROME_BYTES
}

fn analysis_status(complete: bool) -> String {
    let u = ui();
    if complete {
        u.name("complete")
    } else {
        u.warn("incomplete")
    }
}

fn counted(count: usize, singular: &str, plural: &str) -> String {
    format!("{count} {}", if count == 1 { singular } else { plural })
}
