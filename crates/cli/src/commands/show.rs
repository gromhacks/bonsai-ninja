//! `show` — universal stable-id drilldown.
//!
//! This command deliberately delegates to the owning renderer for each
//! id family instead of re-implementing flow/finding formatting:
//! F/G/T -> inspect, E -> dump-edges, N -> dump-ast, R -> dump-resolve,
//! S -> security taint-analysis.

use std::path::{Path, PathBuf};

use anyhow::Result;

use crate::args::{BrowseFormat, InspectView, OutputPathArg, SecurityAction};
use crate::paging;

use super::{
    cmd_dump_ast, cmd_dump_edges, cmd_dump_resolve, cmd_inspect, paging_from_cli, InspectFilters,
    InspectRenderOptions,
};

pub(crate) struct ShowArgs<'a> {
    pub(crate) workspace: &'a Path,
    pub(crate) id: &'a str,
    pub(crate) query: Option<&'a str>,
    pub(crate) in_file: Option<&'a str>,
    pub(crate) compact: bool,
    pub(crate) context: Option<&'a str>,
    pub(crate) page: Option<&'a str>,
    pub(crate) all: bool,
    pub(crate) format: BrowseFormat,
    pub(crate) rules_dir: Option<&'a Path>,
}

pub(crate) fn cmd_show(args: ShowArgs<'_>) -> Result<()> {
    let id = args.id.trim();
    let paging_cfg = paging_from_cli(args.context, args.page, args.all, args.format)?;
    match id_prefix(id)? {
        "F" => show_structural_flow(args.workspace, id, args.compact, paging_cfg, args.format),
        "G" => show_flow_group(args.workspace, id, args.compact, paging_cfg, args.format),
        "T" => show_raw_taint_flow(args.workspace, id, args.compact, paging_cfg, args.format),
        "E" => cmd_dump_edges(
            args.workspace,
            None,
            None,
            None,
            args.compact,
            Some(id),
            0,
            paging_cfg,
            args.format,
        ),
        "N" => cmd_dump_ast(
            args.workspace,
            None,
            None,
            args.compact,
            None,
            Some(id),
            0,
            paging_cfg,
            args.format,
        ),
        "R" => {
            let Some(query) = args.query else {
                anyhow::bail!(
                    "`show {id}` needs `--query <name>` because resolver candidate ids are scoped to the original dump-resolve query"
                );
            };
            cmd_dump_resolve(
                args.workspace,
                query,
                args.in_file,
                args.compact,
                Some(id),
                args.format,
            )
        }
        "S" => show_security_finding(args, id),
        other => anyhow::bail!("unsupported id prefix `{other}:`; expected F:, G:, T:, E:, N:, R:, or S:"),
    }
}

fn show_structural_flow(
    workspace: &Path,
    id: &str,
    compact: bool,
    paging_cfg: paging::PagingConfig,
    format: BrowseFormat,
) -> Result<()> {
    cmd_inspect(
        workspace,
        None,
        false,
        &[],
        InspectFilters::default(),
        usize::MAX,
        usize::MAX,
        usize::MAX,
        InspectRenderOptions {
            compact,
            flow_id_filter: Some(id.to_string()),
            view: InspectView::Trace,
            group_id_filter: None,
        },
        true,
        false,
        false,
        paging_cfg,
        format,
    )
}

fn show_flow_group(
    workspace: &Path,
    id: &str,
    compact: bool,
    paging_cfg: paging::PagingConfig,
    format: BrowseFormat,
) -> Result<()> {
    cmd_inspect(
        workspace,
        None,
        false,
        &[],
        InspectFilters::default(),
        usize::MAX,
        usize::MAX,
        usize::MAX,
        InspectRenderOptions {
            compact,
            flow_id_filter: None,
            view: InspectView::Grouped,
            group_id_filter: Some(id.to_string()),
        },
        true,
        false,
        false,
        paging_cfg,
        format,
    )
}

fn show_raw_taint_flow(
    workspace: &Path,
    id: &str,
    compact: bool,
    paging_cfg: paging::PagingConfig,
    format: BrowseFormat,
) -> Result<()> {
    cmd_inspect(
        workspace,
        None,
        false,
        &[],
        InspectFilters::default(),
        usize::MAX,
        usize::MAX,
        usize::MAX,
        InspectRenderOptions {
            compact,
            flow_id_filter: Some(id.to_string()),
            view: InspectView::Trace,
            group_id_filter: None,
        },
        false,
        true,
        true,
        paging_cfg,
        format,
    )
}

fn show_security_finding(args: ShowArgs<'_>, id: &str) -> Result<()> {
    super::security::cmd_security(
        args.workspace,
        SecurityAction::TaintAnalysis {
            rules_dir: args.rules_dir.map(Path::to_path_buf),
            profile: None,
            source: None,
            finding: Some(id.to_string()),
            trust: None,
            category: None,
            sink: None,
            severity: None,
            tag: None,
            files: Vec::new(),
            exclude_files: Vec::new(),
            inferred_sources: false,
            include_pattern_only: true,
            exclude_tests: false,
            show_sanitized: true,
            taint_budget: None,
            intra_worklist_cap: None,
            context: args.context.map(str::to_string),
            page: args.page.map(str::to_string),
            all: true,
            no_compact: !args.compact,
            summary: false,
            format: args.format,
            baseline: None,
            explain: false,
            output: OutputPathArg {
                output_path: Option::<PathBuf>::None,
            },
        },
    )
}

fn id_prefix(id: &str) -> Result<&str> {
    let Some((prefix, rest)) = id.split_once(':') else {
        anyhow::bail!("stable id `{id}` is missing a prefix; expected F:, G:, T:, E:, N:, R:, or S:");
    };
    if rest.is_empty() {
        anyhow::bail!("stable id `{id}` is missing its hash body");
    }
    Ok(prefix)
}
