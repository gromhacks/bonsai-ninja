//! `bonsai-ninja path` — exact compressed callgraph corridor between endpoints.

use anyhow::Result;
use bonsai_sdk::{EdgeRecord, PathFilters, PathFunctionRow, PathOutcome, PathTerminalCallRow};
use comfy_table::Cell;
use serde::Serialize;

use crate::args::BrowseFormat;
use crate::footer::render_paging_footer;
use crate::page_cache;
use crate::paging;
use crate::progress;
use crate::{cli_println, ui};

use super::{
    open_project_index_matching_any_literal, open_project_index_retrieval_candidate_union,
    open_project_path_query, page_info_to_json, paged_json_incomplete_reasons, short_file,
    workspace_file_count_exceeds,
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
    };
    let stage = progress::ScopedSpinner::new("projecting semantic corridor");
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
        if scoped.edges.is_empty() {
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
    let items = path_graph_items(&outcome);
    match options.format {
        BrowseFormat::Json => emit_path_json(root, &outcome, &options.paging_cfg, filters_hash),
        BrowseFormat::Text => page_cache::emit_paged_text(
            root,
            &items,
            &options.paging_cfg,
            "path",
            filters_hash,
            path_item_cost,
            |items, info, _cfg| {
                render_path_text(&outcome, items);
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
        &path_graph_items(outcome),
        paging_cfg,
        "path",
        filters_hash,
        path_item_cost,
        |items, info, _cfg| {
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
                "representation": outcome.representation,
                "node_count": outcome.node_count,
                "edge_count": outcome.edge_count,
                "analysis_complete": reasons.is_empty(),
                "analysis_incomplete_reasons": reasons,
                "items": items,
                "page": page_info_to_json(info),
            });
            cli_println!("{}", serde_json::to_string_pretty(&wrapped)?);
            Ok(())
        },
    )
}

#[derive(Clone, Serialize)]
#[serde(tag = "kind", content = "evidence", rename_all = "snake_case")]
enum PathGraphItem {
    Node(PathFunctionRow),
    Edge(Box<EdgeRecord>),
    TerminalCall(PathTerminalCallRow),
}

fn path_graph_items(outcome: &PathOutcome) -> Vec<PathGraphItem> {
    outcome
        .nodes
        .iter()
        .cloned()
        .map(PathGraphItem::Node)
        .chain(
            outcome
                .edges
                .iter()
                .cloned()
                .map(|edge| PathGraphItem::Edge(Box::new(edge))),
        )
        .chain(
            outcome
                .terminal_calls
                .iter()
                .cloned()
                .map(PathGraphItem::TerminalCall),
        )
        .collect()
}

fn render_path_text(outcome: &PathOutcome, items: &[PathGraphItem]) {
    let u = ui();
    cli_println!();
    cli_println!(
        "{}",
        u.heading(&format!("▸ path {} → {}", outcome.from, outcome.to))
    );
    cli_println!(
        "  {} {}    {} {}    {} {}    {} {}    {} {}",
        u.label("sources"),
        u.name(&outcome.from_matches.to_string()),
        u.label("targets"),
        u.name(&outcome.to_matches.to_string()),
        u.label("nodes"),
        u.name(&outcome.node_count.to_string()),
        u.label("edges"),
        u.name(&outcome.edge_count.to_string()),
        u.label("status"),
        analysis_status(outcome.analysis_complete)
    );
    cli_println!(
        "  {} {}",
        u.label("representation"),
        u.name(outcome.representation)
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
        u.dim("not loaded (optional)")
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
    if items.is_empty() {
        cli_println!();
        cli_println!("{}", u.dim("(no semantic corridor matched)"));
        return;
    }

    let mut table = u.table(&["kind", "from / symbol", "to / evidence", "location"]);
    for item in items {
        match item {
            PathGraphItem::Node(node) => table.add_row(vec![
                Cell::new(u.kind("node")),
                Cell::new(u.name(&node.name)),
                Cell::new(u.dim("compiler declaration")),
                Cell::new(u.path(&format!("{}:{}", short_file(&node.file), node.line))),
            ]),
            PathGraphItem::Edge(edge) => table.add_row(vec![
                Cell::new(u.kind("edge")),
                Cell::new(u.name(&edge.caller_name)),
                Cell::new(format!("{} · {}", edge.callee_name, edge.resolver_stage)),
                Cell::new(u.path(&format!(
                    "{}:{}:{}",
                    short_file(&edge.call_file),
                    edge.call_line,
                    edge.call_column
                ))),
            ]),
            PathGraphItem::TerminalCall(call) => table.add_row(vec![
                Cell::new(u.kind("terminal-call")),
                Cell::new(u.name(&call.enclosing_function)),
                Cell::new(call.name.clone()),
                Cell::new(u.path(&format!(
                    "{}:{}:{}",
                    short_file(&call.file),
                    call.line,
                    call.column
                ))),
            ]),
        };
    }
    cli_println!("{table}");
}

fn path_item_cost(item: &PathGraphItem) -> u64 {
    serde_json::to_string(item).map_or(256, |encoded| {
        encoded.len() as u64 + paging::TABLE_ROW_CHROME_BYTES
    })
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
