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
    browse::workspace_file_count_exceeds, open_project_index_matching_any_literal,
    open_project_index_retrieval_candidate_union, open_project_path_query, page_info_to_json,
    paged_json_incomplete_reasons, short_file,
};

const PATH_ENDPOINT_PREFILTER_FILE_LIMIT: usize = 5_000;

pub(crate) struct PathCommandOptions<'a> {
    pub(crate) from: &'a str,
    pub(crate) to: &'a str,
    pub(crate) regex: bool,
    pub(crate) paging_cfg: paging::PagingConfig,
    pub(crate) format: BrowseFormat,
}

pub(crate) fn cmd_path(root: &std::path::Path, options: PathCommandOptions<'_>) -> Result<()> {
    let filters = PathFilters {
        from: options.from,
        to: options.to,
        regex: options.regex,
        max_paths: 0,
        max_depth: 0,
        max_probes: 0,
    };
    let stage = progress::ScopedSpinner::new("enumerating semantic paths");
    let endpoint_prefilter = !options.regex
        && options.from.trim().len() >= 3
        && options.to.trim().len() >= 3
        && workspace_file_count_exceeds(root, PATH_ENDPOINT_PREFILTER_FILE_LIMIT);
    let mut outcome = if endpoint_prefilter {
        let endpoint_queries = [options.from, options.to];
        let retrieval_project = open_project_index_retrieval_candidate_union(
            root,
            &endpoint_queries,
            bonsai_sdk::SearchFilters::default(),
        )?;
        let (project, _footer) = if let Some(project) = retrieval_project {
            project
        } else {
            let literal_storage = endpoint_candidate_literals(options.from, options.to);
            let literals = literal_storage.iter().map(String::as_str).collect::<Vec<_>>();
            open_project_index_matching_any_literal(root, &literals)?
        };
        let scoped = project.browse().paths(filters)?;
        if scoped.paths.is_empty() {
            let (project, _footer) = open_project_path_query(root)?;
            project.browse().paths(filters)?
        } else if scoped
            .backends
            .iter()
            .any(|backend| backend.starts_with("partitioned-resolved-callgraph-"))
        {
            scoped
        } else {
            // Raw/retrieval candidates are only a planning accelerator. They
            // cannot prove that an intermediate path in another file does
            // not exist. Without an integrity-checked partitioned graph,
            // reopen the complete lazy compiler snapshot and answer exactly.
            let (project, _footer) = open_project_path_query(root)?;
            project.browse().paths(filters)?
        }
    } else {
        let (project, _footer) = open_project_path_query(root)?;
        project.browse().paths(filters)?
    };
    outcome.analysis_incomplete_reasons.sort();
    outcome.analysis_incomplete_reasons.dedup();
    stage.finish();
    let filters_hash = paging::hash_filters(&[
        ("from", options.from),
        ("to", options.to),
        ("regex", if options.regex { "1" } else { "0" }),
    ]);
    match options.format {
        BrowseFormat::Json => emit_path_json(root, &outcome, &options.paging_cfg, filters_hash),
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

fn endpoint_candidate_literals(from: &str, to: &str) -> Vec<String> {
    let mut literals = Vec::new();
    for endpoint in [from, to] {
        let endpoint = endpoint.trim();
        if endpoint.len() >= 3 {
            literals.push(endpoint.to_string());
        }
        literals.extend(
            endpoint
                .split(|ch: char| !(ch.is_alphanumeric() || ch == '_'))
                .filter(|part| part.len() >= 3)
                .map(str::to_string),
        );
    }
    literals.sort();
    literals.dedup();
    literals
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

#[cfg(test)]
mod tests {
    use super::endpoint_candidate_literals;

    #[test]
    fn qualified_path_endpoints_retain_source_level_tokens() {
        assert_eq!(
            endpoint_candidate_literals(
                "AbstractHttpServerTransport.dispatchRequest",
                "server::RestController#dispatchRequest",
            ),
            vec![
                "AbstractHttpServerTransport".to_string(),
                "AbstractHttpServerTransport.dispatchRequest".to_string(),
                "RestController".to_string(),
                "dispatchRequest".to_string(),
                "server".to_string(),
                "server::RestController#dispatchRequest".to_string(),
            ]
        );
    }
}
