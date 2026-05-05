//! Closing-footer chrome printed at the end of every CLI command.
//!
//! Two footers can fire:
//!
//! - [`render_workspace_footer`] — generic "N lines · X KB · ~Y tokens"
//!   summary. Runs from [`WorkspaceFooter`]'s `Drop`, so it fires on
//!   the Ok AND error exit of every command that opened a workspace.
//! - [`render_paging_footer`] — paginated-table footer with page
//!   number / budget / cursor. Fired inline by the command's text
//!   renderer.
//!
//! The two are exclusive by design: when `render_paging_footer`
//! fires, it sets [`PAGING_FOOTER_FIRED`] and `render_workspace_footer`
//! stays silent — printing both would duplicate the token total in a
//! confusing way (workspace footer counts the paging footer's own
//! output, so its number is always larger and drifts from what the
//! user would report).

use std::sync::atomic::{AtomicBool, Ordering};

use crate::paging;
use crate::progress;
use crate::{cli_println, out_count, page_cache, ui};

/// Set by [`render_paging_footer`] when it emits. Read by
/// [`render_workspace_footer`] (fired by [`WorkspaceFooter`]'s
/// `Drop`) so we don't double-print a redundant token total. One-
/// way latch per process — once paging fires, no workspace footer
/// for the rest of the invocation.
pub(crate) static PAGING_FOOTER_FIRED: AtomicBool = AtomicBool::new(false);

/// RAII guard whose `Drop` prints the one-line summary of the
/// stdout output (lines + bytes + approximate LLM tokens) to
/// stderr when the command finishes. Held for the duration of a
/// command so the footer fires on `Ok` OR error paths.
///
/// Renders only when stderr is a TTY and chrome isn't muted
/// (`--no-progress` / `NO_PROGRESS` / `NO_COLOR`), so JSON pipes
/// and CI runs stay clean.
pub(crate) struct WorkspaceFooter;

impl WorkspaceFooter {
    pub(crate) fn new() -> Self {
        Self
    }
}

impl Drop for WorkspaceFooter {
    fn drop(&mut self) {
        render_workspace_footer();
    }
}

/// Compute + print the one-line output summary. Stderr-only so
/// stdout (JSON, reports) remains clean for scripting.
///
/// Reports what THIS command produced, not the workspace at large:
///
/// - **lines** — total newline-terminated lines written to stdout
///   by `cli_println!` / `cli_print!`.
/// - **bytes** — total stdout byte count in B / KB / MB.
/// - **tokens** — approximate LLM-style count using the standard
///   ~4-bytes-per-token heuristic for latin-script code (matches
///   the GPT-family BPE average). Fast to compute and stable
///   enough to tell a user "will this fit my context window."
///
/// Commands that produced nothing (machine-readable JSON pipes via
/// `--format json`, silent ok-paths) still get a concise 0-line
/// summary rather than surprise empty output.
pub(crate) fn render_workspace_footer() {
    if !progress::is_footer_enabled() {
        return;
    }
    // The paging footer (`page N of M · context U/B tokens (pct%)`)
    // already surfaces the same information — line/byte/token
    // totals, specific to the rows shown — plus the next-page hint.
    // Printing the workspace summary underneath duplicates the
    // token number in a less-useful way.
    if PAGING_FOOTER_FIRED.load(Ordering::Relaxed) {
        return;
    }
    let ui = ui();
    let bytes = out_count::bytes();
    let lines = out_count::lines();
    let tokens_approx = bytes / 4; // GPT-ish BPE ballpark
    eprintln!();
    eprintln!(
        "{}  {} lines · {} · ~{} estimated tokens",
        ui.label("output"),
        ui.name(&format_count(lines)),
        ui.name(&format_bytes(bytes)),
        ui.name(&format_count(tokens_approx)),
    );
}

/// Thousands-separator formatter, locale-independent.
/// `1234567 → "1,234,567"`. Small deps-free helper.
pub(crate) fn format_count(n: usize) -> String {
    let s = n.to_string();
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len() + s.len() / 3);
    for (i, &b) in bytes.iter().enumerate() {
        if i > 0 && (bytes.len() - i) % 3 == 0 {
            out.push(',');
        }
        out.push(b as char);
    }
    out
}

/// Compact byte-size renderer: `B` / `KB` / `MB` / `GB` with one
/// decimal place on the larger units. Matches `du -h` feel.
pub(crate) fn format_bytes(n: usize) -> String {
    const KB: usize = 1024;
    const MB: usize = KB * 1024;
    const GB: usize = MB * 1024;
    if n >= GB {
        format!("{:.1} GB", n as f64 / GB as f64)
    } else if n >= MB {
        format!("{:.1} MB", n as f64 / MB as f64)
    } else if n >= KB {
        format!("{:.1} KB", n as f64 / KB as f64)
    } else {
        format!("{n} B")
    }
}

/// Render the optional "showing N of TOTAL" footer after a browse
/// table. Silently no-ops when nothing was truncated. The message
/// is dim-styled so it doesn't steal focus from the table.
pub(crate) fn render_truncation_notice(shown: usize, total_if_truncated: Option<usize>) {
    if let Some(total) = total_if_truncated {
        let u = ui();
        cli_println!(
            "{}",
            u.dim(&format!(
                "showing {shown} of {total} — pass --limit 0 or --format json for all",
            ))
        );
    }
}

/// Render the paging footer below a paginated text table: page
/// number / total pages, context-budget usage, and the two copyable
/// resume forms (content-hash cursor + 1-based page number). When
/// the page is the last one, the `next` line is replaced by a
/// dim `end of results` line so the reader doesn't chase a
/// non-existent next page. Silently no-ops when paging produced
/// only one page AND the run wasn't explicitly budgeted — the
/// common small-fixture case stays uncluttered.
pub(crate) fn render_paging_footer(info: &paging::PageInfo, cmd_line_hint: &str) {
    // Single-page, no budget → nothing worth printing.
    if info.is_last && info.page_number == 1 && info.budget.is_none() && info.total_pages == 1 {
        return;
    }
    // Mark the paging footer as active so `render_workspace_footer`
    // (fired later via `WorkspaceFooter`'s `Drop`) stays silent.
    PAGING_FOOTER_FIRED.store(true, Ordering::Relaxed);
    let u = ui();
    let more_on_next = info
        .next_cursor
        .as_ref()
        .map(|_| info.total_rows.saturating_sub(info.shown_rows))
        .unwrap_or(0);
    let page_line = if info.total_pages > 1 {
        if info.is_last {
            format!(
                "page {} of {} ({} rows)",
                info.page_number, info.total_pages, info.shown_rows
            )
        } else if more_on_next > 0 {
            // Accurate row count for the next page — show it inline.
            format!(
                "page {} of {} ({} rows)  —  {more_on_next} more on page {}",
                info.page_number,
                info.total_pages,
                info.shown_rows,
                info.page_number + 1,
            )
        } else {
            // `next_cursor` is set but the row counter doesn't
            // reflect what's left (e.g. inspect truncated its
            // OCCURRENCE or folded-flow sections, which don't
            // live in the `shown_rows` / `total_rows` accounting).
            // Drop the misleading "0 more" suffix.
            format!(
                "page {} of {} ({} rows)  —  more on page {}",
                info.page_number,
                info.total_pages,
                info.shown_rows,
                info.page_number + 1,
            )
        }
    } else {
        format!("page 1 of 1 ({} rows)", info.shown_rows)
    };
    cli_println!("{}", u.dim(&page_line));
    cli_println!(
        "{}",
        u.dim(&format!(
            "total   {} {}",
            format_count(info.total_rows as usize),
            paging_total_label(cmd_line_hint, info.total_rows),
        ))
    );
    // Footer reports ACTUAL rendered tokens, not the paginator's
    // pre-render estimate. Earlier implementations showed
    // `info.tokens_used`, which is the sum of per-row cost
    // estimates — great for planning what fits on a page, but it
    // drifts from reality when a cost function underestimates (see
    // `security taint-analysis`'s Finding cost, which ignored the inspect
    // FLOW body bytes and reported 93% of a 4K budget while
    // actually emitting ~11K tokens of content). Counting visible
    // bytes out of `out_count` post-render and dividing by 4 gives
    // the reader the same number any external tokenizer would.
    let actual_tokens = if let Some(bytes) = page_cache::captured_bytes() {
        paging::bytes_to_tokens(bytes as u64)
    } else {
        let actual_bytes = out_count::bytes() as u64;
        paging::bytes_to_tokens(actual_bytes)
    };
    if let Some(budget) = info.budget {
        let pct = if budget > 0 {
            (actual_tokens as f64 / budget as f64 * 100.0) as u64
        } else {
            0
        };
        // The "full uncapped" hint scales from the paginator's per-
        // row cost sum. When that sum underreports the truth, scale
        // it by the ratio of actual-rendered-tokens to
        // paginator-estimated-tokens-on-this-page so the uncapped
        // projection stays in the same order of magnitude as the
        // page the reader is holding. When the estimate matches
        // reality the ratio is ~1.0 and the number is unchanged.
        let estimated_page_tokens = info.tokens_used.max(1);
        let scale = actual_tokens as f64 / estimated_page_tokens as f64;
        let projected_uncapped = (info.total_tokens_uncapped as f64 * scale).round() as u64;
        let uncapped_hint = if projected_uncapped > actual_tokens {
            format!(
                "  ·  full uncapped: ~{} tokens",
                format_count(projected_uncapped as usize)
            )
        } else {
            String::new()
        };
        cli_println!(
            "{}",
            u.dim(&format!(
                "context  {} / {} tokens ({pct}%){uncapped_hint}",
                format_count(actual_tokens as usize),
                format_count(budget as usize),
            ))
        );
        if actual_tokens > budget {
            // Distinguish the two reasons a page can exceed its
            // budget. When the actual-rendered total roughly matches
            // the paginator's own pre-render estimate, the budget
            // was blown by a single oversized row that the paginator
            // preserved on purpose (the "don't render nothing"
            // guarantee — spec-level). When actual ≫ estimate the
            // cost function itself was short, which is an
            // actionable bug to tune.
            let estimate = info.tokens_used as f64;
            let ratio = if estimate > 0.0 {
                actual_tokens as f64 / estimate
            } else {
                1.0
            };
            if ratio <= 1.15 {
                cli_println!(
                    "{}",
                    u.dim(
                        "         (single row cost exceeded --context; rendered anyway to preserve context)"
                    )
                );
            } else {
                cli_println!(
                    "{}",
                    u.dim(
                        "         (rendered output exceeded --context budget; page cost estimate was short)"
                    )
                );
            }
        }
    } else if info.total_tokens_uncapped > 0 || actual_tokens > 0 {
        // Even without a budget (e.g. `--all`) report the actual
        // rendered tokens — what the reader is about to paste into
        // any LLM context window.
        cli_println!(
            "{}",
            u.dim(&format!(
                "context  ~{} tokens (uncapped)",
                format_count(actual_tokens as usize)
            ))
        );
    }
    if let Some(next) = &info.next_cursor {
        cli_println!("{}", u.dim(&format!("next     {cmd_line_hint} --page {next}")));
        cli_println!(
            "{}",
            u.dim(&format!(
                "         {cmd_line_hint} --page {}",
                info.page_number + 1
            ))
        );
    } else {
        cli_println!("{}", u.dim("end of results"));
    }
}

fn paging_total_label(cmd_line_hint: &str, total: u64) -> &'static str {
    let singular = total == 1;
    let pluralize = |one: &'static str, many: &'static str| if singular { one } else { many };
    if cmd_line_hint.contains(" security <workspace> taint-analysis") {
        pluralize("tainted flow", "tainted flows")
    } else if cmd_line_hint.contains(" security <workspace> source-analysis") {
        pluralize("source flow", "source flows")
    } else if cmd_line_hint.contains(" security <workspace> sources") {
        pluralize("taint source", "taint sources")
    } else if cmd_line_hint.contains(" security <workspace> sinks") {
        pluralize("sink", "sinks")
    } else if cmd_line_hint.contains(" security <workspace> sanitizers") {
        pluralize("sanitizer", "sanitizers")
    } else if cmd_line_hint.contains(" security <workspace> deps") {
        pluralize("dependency finding", "dependency findings")
    } else if cmd_line_hint.contains(" security <workspace> pack")
        || cmd_line_hint.contains(" security <ws> pack")
    {
        pluralize("rule", "rules")
    } else if cmd_line_hint.contains(" defs ") {
        pluralize("definition", "definitions")
    } else if cmd_line_hint.contains(" calls ") {
        pluralize("call site", "call sites")
    } else if cmd_line_hint.contains(" imports ") {
        pluralize("unique import", "unique imports")
    } else if cmd_line_hint.contains(" vars ") {
        pluralize("variable", "variables")
    } else if cmd_line_hint.contains(" strings ") {
        pluralize("string literal", "string literals")
    } else if cmd_line_hint.contains(" comments ") {
        pluralize("comment", "comments")
    } else if cmd_line_hint.contains(" args ") {
        pluralize("argument", "arguments")
    } else if cmd_line_hint.contains(" classes ") {
        pluralize("class", "classes")
    } else if cmd_line_hint.contains(" refs ") {
        pluralize("reference", "references")
    } else if cmd_line_hint.contains(" search ") {
        pluralize("match", "matches")
    } else if cmd_line_hint.contains(" inspect ") {
        pluralize("flow/render unit", "flow/render units")
    } else if cmd_line_hint.contains(" trace ") {
        pluralize("trace line", "trace lines")
    } else if cmd_line_hint.contains(" tree ") {
        pluralize("tree line", "tree lines")
    } else if cmd_line_hint.contains(" read-file ") {
        pluralize("line", "lines")
    } else if cmd_line_hint.contains(" dump-callgraph ") {
        pluralize("callgraph edge", "callgraph edges")
    } else if cmd_line_hint.contains(" dump-edges ") {
        pluralize("dataflow edge", "dataflow edges")
    } else if cmd_line_hint.contains(" dump-ast ") {
        pluralize("AST line", "AST lines")
    } else {
        pluralize("row", "rows")
    }
}
