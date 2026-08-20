//! `bonsai-ninja slice` — exact backwards slice for one symbol.

use anyhow::Result;
use bonsai_sdk::{SliceFilters, SliceOutcome, SliceRow, SliceStep};
use comfy_table::Cell;

use crate::args::BrowseFormat;
use crate::footer::render_paging_footer;
use crate::page_cache;
use crate::paging;
use crate::progress;
use crate::{cli_println, ui};

use super::{
    open_project_index_filtered_paths, open_project_index_matching_literal, page_info_to_json,
    paged_json_incomplete_reasons, short_file,
};

pub(crate) fn cmd_slice(
    root: &std::path::Path,
    symbol: &str,
    line: Option<u32>,
    file: Option<&str>,
    paging_cfg: paging::PagingConfig,
    format: BrowseFormat,
) -> Result<()> {
    let (project, _footer) = if let Some(file) = file.filter(|file| !file.trim().is_empty()) {
        open_project_index_filtered_paths(root, &[file.to_string()], &[])?
    } else {
        // Compiler-qualified selectors are not required to occur verbatim in
        // source. Use only their declaration token for lexical candidate
        // selection; the slice engine resolves the complete selector against
        // typed declarations.
        open_project_index_matching_literal(root, bonsai_callgraph::short_callee(symbol))?
    };
    let filters = SliceFilters {
        symbol,
        line: line.unwrap_or(0),
        file,
        max_steps: 0,
    };
    let stage = progress::ScopedSpinner::new("slicing syntax flow");
    let outcome = project.browse().slices(filters);
    stage.finish();
    let line_s = line.map_or_else(|| "auto".to_string(), |line| line.to_string());
    let filters_hash = paging::hash_filters(&[
        ("symbol", symbol),
        ("line", line_s.as_str()),
        ("file", file.unwrap_or("")),
    ]);
    match format {
        BrowseFormat::Json => emit_slice_json(root, &outcome, &paging_cfg, filters_hash),
        BrowseFormat::Text => page_cache::emit_paged_text(
            root,
            &outcome.slices,
            &paging_cfg,
            "slice",
            filters_hash,
            slice_cost,
            |slices, info, _cfg| {
                render_slice_text(&outcome, slices);
                render_paging_footer(info, "bonsai-ninja slice <workspace> --symbol <x> [--line <N>]");
                Ok(())
            },
        ),
    }
}

fn emit_slice_json(
    root: &std::path::Path,
    outcome: &SliceOutcome,
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
        &outcome.slices,
        paging_cfg,
        "slice",
        filters_hash,
        slice_cost,
        |slices, info, _cfg| {
            if !force_wrapper && info.page_number == 1 && info.is_last {
                cli_println!("{}", serde_json::to_string_pretty(outcome)?);
                return Ok(());
            }
            let mut reasons = outcome.analysis_incomplete_reasons.clone();
            reasons.extend(paged_json_incomplete_reasons("slice", info));
            reasons.sort();
            reasons.dedup();
            let wrapped = serde_json::json!({
                "symbol": outcome.symbol,
                "line": outcome.line,
                "file": outcome.file,
                "candidate_count": outcome.candidate_count,
                "slice_count": outcome.slice_count,
                "max_steps": outcome.max_steps,
                "backends": outcome.backends,
                "analysis_complete": reasons.is_empty(),
                "analysis_incomplete_reasons": reasons,
                "slices": slices,
                "page": page_info_to_json(info),
            });
            cli_println!("{}", serde_json::to_string_pretty(&wrapped)?);
            Ok(())
        },
    )
}

fn render_slice_text(outcome: &SliceOutcome, slices: &[SliceRow]) {
    let u = ui();
    cli_println!();
    cli_println!(
        "{}",
        u.heading(&if outcome.line == 0 {
            format!("▸ slice {}", outcome.symbol)
        } else {
            format!("▸ slice {} @ line {}", outcome.symbol, outcome.line)
        })
    );
    cli_println!(
        "  {} {}    {} {}    {} {}    {} {}",
        u.label("candidates"),
        u.name(&outcome.candidate_count.to_string()),
        u.label("slices"),
        u.name(&outcome.slice_count.to_string()),
        u.label("limit"),
        u.name(&step_limit(outcome.max_steps)),
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
    if let Some(file) = outcome.file.as_deref() {
        cli_println!("  {} {}", u.label("file"), u.path(file));
    }
    if !outcome.analysis_incomplete_reasons.is_empty() {
        for line in
            u.wrapped_warn_labeled_lines("incomplete", &outcome.analysis_incomplete_reasons.join("; "))
        {
            cli_println!("{line}");
        }
    }
    if slices.is_empty() {
        cli_println!();
        cli_println!("{}", u.dim("(no slice matched)"));
        return;
    }

    for slice in slices {
        cli_println!();
        cli_println!(
            "{} {}  {}",
            u.label("SLICE"),
            u.name(&slice.slice_id),
            u.dim(&format!(
                "{}:{} in {} [{} step(s)]",
                short_file(&slice.file),
                slice.target_line,
                slice.function,
                slice.step_count
            ))
        );
        if !slice.influencing_symbols.is_empty() {
            cli_println!(
                "  {} {}",
                u.label("influences"),
                u.name(&slice.influencing_symbols.join(", "))
            );
        }
        if !slice.backends.is_empty() {
            cli_println!("  {} {}", u.label("backends"), u.name(&slice.backends.join(", ")));
        }
        if !slice.analysis_incomplete_reasons.is_empty() {
            for line in
                u.wrapped_warn_labeled_lines("incomplete", &slice.analysis_incomplete_reasons.join("; "))
            {
                cli_println!("{line}");
            }
        }
        let mut table = u.table(&["#", "kind", "symbol", "location", "detail", "sources"]);
        for (idx, step) in slice.steps.iter().enumerate() {
            table.add_row(vec![
                Cell::new(u.dim(&(idx + 1).to_string())),
                Cell::new(&step.kind),
                Cell::new(u.name(&step.symbol)),
                Cell::new(u.path(&step_location(step))),
                Cell::new(&step.detail),
                Cell::new(u.dim(&step.sources.join(", "))),
            ]);
        }
        cli_println!("{table}");
    }
}

fn step_location(step: &SliceStep) -> String {
    if step.line == 0 {
        return "parameter".to_string();
    }
    format!("{}:{}", short_file(&step.file), step.line)
}

fn slice_cost(slice: &SliceRow) -> u64 {
    let steps = slice
        .steps
        .iter()
        .map(|step| {
            step.kind.len()
                + step.symbol.len()
                + step.file.len()
                + step.detail.len()
                + step.sources.iter().map(String::len).sum::<usize>()
                + 48
        })
        .sum::<usize>();
    (slice.file.len()
        + slice.function.len()
        + slice.target_symbol.len()
        + slice.backends.iter().map(String::len).sum::<usize>()
        + slice.influencing_symbols.iter().map(String::len).sum::<usize>()
        + steps
        + 160) as u64
        + paging::TABLE_ROW_CHROME_BYTES
}

fn analysis_status(complete: bool) -> String {
    let u = ui();
    if complete {
        u.name("complete")
    } else {
        u.warn("incomplete")
    }
}

fn step_limit(max_steps: usize) -> String {
    if max_steps == 0 {
        "uncapped".to_string()
    } else {
        counted(max_steps, "step", "steps")
    }
}

fn counted(count: usize, singular: &str, plural: &str) -> String {
    format!("{count} {}", if count == 1 { singular } else { plural })
}
