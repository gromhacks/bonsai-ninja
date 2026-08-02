//! `show` — universal stable-id drilldown.
//!
//! This command deliberately delegates to the owning renderer for each
//! id family instead of re-implementing flow/finding formatting:
//! F/G security ids -> security, structural fallback -> inspect,
//! raw-inspect T -> inspect, structured dump-taint T -> dump-taint,
//! E -> dump-edges, N -> dump-ast, R -> dump-resolve, S/security G ->
//! security taint-analysis. SDK structural-chain fallback is used only
//! for structural F/G ids that the SDK exposes but the downstream
//! inspect renderer does not print for the same query shape.

use std::path::{Path, PathBuf};

use anyhow::Result;

use crate::args::{BrowseFormat, InspectView, OutputPathArg, SecurityAction};
use crate::cli_println;
use crate::paging;

use super::{
    cmd_dump_ast, cmd_dump_edges, cmd_dump_resolve, cmd_dump_taint, cmd_inspect, open_project_index_only,
    paging_from_cli, InspectCommandOptions, InspectFilters, InspectRenderOptions,
};

pub(crate) struct ShowArgs<'a> {
    pub(crate) workspace: &'a Path,
    pub(crate) id: &'a str,
    pub(crate) query: Option<&'a str>,
    pub(crate) in_file: Option<&'a str>,
    pub(crate) taint_source: Option<&'a str>,
    pub(crate) taint_seeds: &'a [String],
    pub(crate) taint_sink: Option<&'a str>,
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
    let prefix = id_prefix(id)?;
    if prefix != "T" && args.has_dump_taint_context() {
        anyhow::bail!(
            "dump-taint show options (`--taint-source`, `--taint-seed`, `--taint-sink`) only apply to T: ids"
        );
    }
    match prefix {
        "F" => show_security_or_structural_flow(&args, id, paging_cfg),
        "G" => show_security_or_structural_group(&args, id, paging_cfg),
        "T" if args.has_dump_taint_context() => show_dump_taint_propagation(args, id, paging_cfg),
        "T" => {
            show_raw_taint_flow(args.workspace, id, args.compact, paging_cfg, args.format).map_err(|err| {
                if err.to_string().contains("no flow matching") {
                    anyhow::anyhow!(
                        "{err} `dump-taint` propagation ids share the T: prefix but are \
                         source-seeded: reopen those with `show {id} --taint-source <function> \
                         [--taint-seed <param>]`."
                    )
                } else {
                    err
                }
            })
        }
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

impl ShowArgs<'_> {
    fn has_dump_taint_context(&self) -> bool {
        self.taint_source.is_some() || !self.taint_seeds.is_empty() || self.taint_sink.is_some()
    }
}

fn show_structural_flow(
    workspace: &Path,
    id: &str,
    query: Option<&str>,
    is_regex: bool,
    compact: bool,
    paging_cfg: paging::PagingConfig,
    format: BrowseFormat,
) -> Result<()> {
    cmd_inspect(
        workspace,
        InspectCommandOptions {
            pattern: query,
            is_regex,
            kind_filter: &[],
            filters: InspectFilters::default(),
            render: InspectRenderOptions {
                compact,
                flow_id_filter: Some(id.to_string()),
                view: InspectView::Trace,
                group_id_filter: None,
                structural_drilldown: true,
            },
            graph_flow: true,
            taint_flow: false,
            paging_cfg,
            format,
        },
    )
}

fn show_security_or_structural_flow(
    args: &ShowArgs<'_>,
    id: &str,
    paging_cfg: paging::PagingConfig,
) -> Result<()> {
    // An explicit query, or a fresh breadcrumb recorded when inspect emitted
    // this id, identifies it as structural and restores the exact narrow
    // compiler scope. Never speculatively open the security taint engine for
    // a structural id merely because both historical APIs use `F:`.
    if let Some(query) = args.query {
        return show_structural_flow(
            args.workspace,
            id,
            Some(query),
            false,
            args.compact,
            paging_cfg,
            args.format,
        );
    }
    if args.rules_dir.is_none() {
        if let Some(hint) = crate::page_cache::structural_id_hint(args.workspace, id)? {
            return show_structural_flow(
                args.workspace,
                id,
                Some(&hint.query),
                hint.regex,
                args.compact,
                paging_cfg,
                args.format,
            );
        }
    }
    // Security and structural flows historically share the F: namespace.
    // Probe the exact flow-filtered security facade first: production output
    // is the most common source of pasted F: ids, and the sparse IDG query is
    // bounded by that id. Starting with unfiltered structural inspect used to
    // enumerate an entire large-repository graph before discovering that the
    // id belonged to security (eight minutes on Elasticsearch).
    match show_security_flow(args, id) {
        Ok(()) => Ok(()),
        Err(security_err) => {
            match show_structural_flow(
                args.workspace,
                id,
                None,
                false,
                args.compact,
                paging_cfg.clone(),
                args.format,
            ) {
                Ok(()) => Ok(()),
                Err(err) if err.to_string().contains("no flow matching") => {
                    match show_sdk_structural_flow(args.workspace, id, args.format) {
                        Ok(()) => Ok(()),
                        Err(sdk_err) => Err(anyhow::anyhow!(
                            "flow id `{id}` was not found by security taint flow, inspect render, or SDK structural chains: {security_err}; {err}; {sdk_err}"
                        )),
                    }
                }
                Err(err) => Err(err),
            }
        }
    }
}

fn show_flow_group(
    workspace: &Path,
    id: &str,
    query: Option<&str>,
    is_regex: bool,
    compact: bool,
    paging_cfg: paging::PagingConfig,
    format: BrowseFormat,
) -> Result<()> {
    cmd_inspect(
        workspace,
        InspectCommandOptions {
            pattern: query,
            is_regex,
            kind_filter: &[],
            filters: InspectFilters::default(),
            render: InspectRenderOptions {
                compact,
                flow_id_filter: None,
                view: InspectView::Grouped,
                group_id_filter: Some(id.to_string()),
                structural_drilldown: true,
            },
            graph_flow: true,
            taint_flow: false,
            paging_cfg,
            format,
        },
    )
}

fn show_security_or_structural_group(
    args: &ShowArgs<'_>,
    id: &str,
    paging_cfg: paging::PagingConfig,
) -> Result<()> {
    if let Some(query) = args.query {
        return show_flow_group(
            args.workspace,
            id,
            Some(query),
            false,
            args.compact,
            paging_cfg,
            args.format,
        );
    }
    if args.rules_dir.is_none() {
        if let Some(hint) = crate::page_cache::structural_id_hint(args.workspace, id)? {
            return show_flow_group(
                args.workspace,
                id,
                Some(&hint.query),
                hint.regex,
                args.compact,
                paging_cfg,
                args.format,
            );
        }
    }
    match show_security_group(args, id) {
        Ok(()) => Ok(()),
        Err(security_err) => {
            match show_flow_group(
                args.workspace,
                id,
                None,
                false,
                args.compact,
                paging_cfg.clone(),
                args.format,
            ) {
                Ok(()) => Ok(()),
                Err(err) if err.to_string().contains("no flow group matching") => {
                    match show_sdk_structural_group(args.workspace, id, args.format) {
                        Ok(()) => Ok(()),
                        Err(sdk_err) => Err(anyhow::anyhow!(
                            "group id `{id}` was not found by security taint group, inspect render, or SDK structural chains: {security_err}; {err}; {sdk_err}"
                        )),
                    }
                }
                Err(err) => Err(err),
            }
        }
    }
}

/*
 * Keep the structural renderers below independent of routing. The F:/G:
 * namespace predates security flow ids, so compatibility still requires both
 * owners; the router above only changes probe order and never changes result
 * semantics.
 */

fn show_sdk_structural_flow(workspace: &Path, id: &str, format: BrowseFormat) -> Result<()> {
    let (project, _footer) = open_project_index_only(workspace)?;
    match project.show().structural_flow(id)? {
        bonsai_sdk::ShowOutcome::InspectFlow(flow) => emit_sdk_inspect_flow(&flow, format),
        other => anyhow::bail!("SDK structural flow lookup returned unexpected outcome: {other:?}"),
    }
}

fn show_sdk_structural_group(workspace: &Path, id: &str, format: BrowseFormat) -> Result<()> {
    let (project, _footer) = open_project_index_only(workspace)?;
    match project.show().flow_group(id)? {
        bonsai_sdk::ShowOutcome::InspectFlowGroup(group) => emit_sdk_inspect_group(&group, format),
        other => anyhow::bail!("SDK structural group lookup returned unexpected outcome: {other:?}"),
    }
}

fn emit_sdk_inspect_flow(flow: &bonsai_sdk::InspectFlowShow, format: BrowseFormat) -> Result<()> {
    match format {
        BrowseFormat::Json => {
            cli_println!("{}", serde_json::to_string_pretty(flow)?);
        }
        BrowseFormat::Text => {
            cli_println!("FLOW {}", flow.flow_id);
            for matched in &flow.matches {
                cli_println!(
                    "{}  target={}  chain={}",
                    matched.target_func_id,
                    matched.target,
                    matched.chain.names.join(" -> ")
                );
            }
        }
    }
    Ok(())
}

fn emit_sdk_inspect_group(group: &bonsai_sdk::InspectFlowGroupShow, format: BrowseFormat) -> Result<()> {
    match format {
        BrowseFormat::Json => {
            cli_println!("{}", serde_json::to_string_pretty(group)?);
        }
        BrowseFormat::Text => {
            cli_println!("GROUP {}  {} match(es)", group.group_id, group.matches.len());
            for matched in &group.matches {
                cli_println!(
                    "{}  target={}  group={}  members={}",
                    matched.target_func_id,
                    matched.target,
                    matched.group.group_id,
                    matched.group.member_flow_ids.join(", ")
                );
            }
        }
    }
    Ok(())
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
        InspectCommandOptions {
            pattern: None,
            is_regex: false,
            kind_filter: &[],
            filters: InspectFilters::default(),
            render: InspectRenderOptions {
                compact,
                flow_id_filter: Some(id.to_string()),
                view: InspectView::Trace,
                group_id_filter: None,
                structural_drilldown: true,
            },
            graph_flow: false,
            taint_flow: true,
            paging_cfg,
            format,
        },
    )
}

fn show_dump_taint_propagation(args: ShowArgs<'_>, id: &str, paging_cfg: paging::PagingConfig) -> Result<()> {
    let Some(source) = args.taint_source else {
        anyhow::bail!(
            "`show {id}` with dump-taint filters needs `--taint-source <function>` because structured T: propagation ids are source-seeded"
        );
    };
    cmd_dump_taint(
        args.workspace,
        source,
        args.taint_seeds,
        args.taint_sink,
        args.compact,
        Some(id),
        paging_cfg,
        args.format,
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
            flow: None,
            group: None,
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
            context: args.context.map(str::to_string),
            page: args.page.map(str::to_string),
            all: args.all,
            summary: false,
            format: args.format.into(),
            baseline: None,
            explain: false,
            output: OutputPathArg {
                output_path: Option::<PathBuf>::None,
            },
        },
    )
}

fn show_security_flow(args: &ShowArgs<'_>, id: &str) -> Result<()> {
    super::security::cmd_security(
        args.workspace,
        SecurityAction::TaintAnalysis {
            rules_dir: args.rules_dir.map(Path::to_path_buf),
            profile: None,
            source: None,
            finding: None,
            flow: Some(id.to_string()),
            group: None,
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
            context: args.context.map(str::to_string),
            page: args.page.map(str::to_string),
            all: args.all,
            summary: false,
            format: args.format.into(),
            baseline: None,
            explain: false,
            output: OutputPathArg {
                output_path: Option::<PathBuf>::None,
            },
        },
    )
}

fn show_security_group(args: &ShowArgs<'_>, id: &str) -> Result<()> {
    super::security::cmd_security(
        args.workspace,
        SecurityAction::TaintAnalysis {
            rules_dir: args.rules_dir.map(Path::to_path_buf),
            profile: None,
            source: None,
            finding: None,
            flow: None,
            group: Some(id.to_string()),
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
            context: args.context.map(str::to_string),
            page: args.page.map(str::to_string),
            all: args.all,
            summary: false,
            format: args.format.into(),
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
