//! Context-window aware pagination for row-based CLI commands.
//!
//! Two axes: `--context <budget>` (token ceiling, accepts shorthand
//! `4k`..`1m`; default from `BONSAI_CONTEXT` or 32 k for text /
//! uncapped for JSON / CSV / DOT) and `--page <cursor|N>` (resume by
//! content-hash cursor or 1-based page number). Lossless: every row
//! in the uncapped output is reachable by walking pages. `--all` /
//! `--context 0` opts out. See SPEC §13.

use ahash::AHashMap;
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    OnceLock,
};

/// Default context budget when neither `--context` nor
/// `BONSAI_CONTEXT` is set. Chosen to match Ollama's mid-tier local
/// default (24–48 GiB VRAM) so `bonsai-ninja <cmd> ./src` on a
/// typical dev laptop fits a 32 k-context model out of the box.
pub(crate) const DEFAULT_CONTEXT_TEXT: u64 = 32_768;

/// Reserve ratio on the context budget. Chrome (headers, footer,
/// truncation notice) costs ~3 % of the budget at every budget
/// size we've measured; shaving 5 % up front keeps the raw row
/// output comfortably below the stated ceiling so the
/// `tokens/budget` percentage never prints 100 %+.
const CHROME_RESERVE: f64 = 0.05;
static CURSOR_FILE_TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// How a row's byte cost converts to a token estimate. Matches the
/// existing token-footer heuristic (~4 ASCII bytes per token for
/// latin-script source). The exact ratio doesn't matter for the
/// paging invariants — what matters is that the SAME ratio is used
/// by the footer's reported `tokens` count, so users see a
/// consistent story.
pub(crate) const BYTES_PER_TOKEN: u64 = 4;

/// Parse a `--context` argument into a token budget.
///
/// Accepted forms:
/// - plain integer (`32768`)
/// - `k` suffix (`32k`, `128k`) — multiply by 1024
/// - `m` suffix (`1m`) — multiply by 1_048_576
/// - `0` or `all` or `uncapped` — returns `None` (no budget).
///
/// Case insensitive. Whitespace trimmed.
pub(crate) fn parse_context(raw: &str) -> Result<Option<u64>, String> {
    let s = raw.trim().to_ascii_lowercase();
    if s.is_empty() || s == "0" || s == "all" || s == "uncapped" || s == "none" {
        return Ok(None);
    }
    let (num_part, mult) = if let Some(stripped) = s.strip_suffix('k') {
        (stripped, 1024_u64)
    } else if let Some(stripped) = s.strip_suffix('m') {
        (stripped, 1024_u64 * 1024)
    } else {
        (s.as_str(), 1)
    };
    let n: u64 = num_part
        .parse()
        .map_err(|_| format!("invalid --context value `{raw}` — expected integer or <N>k / <N>m"))?;
    Ok(Some(n.saturating_mul(mult)))
}

/// Output format for paging purposes — which formats paginate by
/// default and which stay uncapped unless the user opts in.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum FormatClass {
    /// Human-read text output. Paginates by default to the
    /// context budget.
    Text,
    /// Programmatic output (JSON, CSV). Uncapped by default —
    /// scripts consume the whole result set. Opts into paging
    /// when `--context` or `--page` is explicitly set.
    Programmatic,
    /// Render-only output (DOT). Paging a partial graph is
    /// meaningless; these formats always return everything.
    RenderOnly,
}

/// The page identity requested on the command line. Internally
/// resolves to a zero-based row offset plus a per-page cap.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum PageArg {
    /// No `--page` flag — start at page 1 (offset 0).
    First,
    /// Numeric `--page 3` — zero-based page index is `N - 1`.
    Number(u64),
    /// Content-hash `--page P:xxxxxxxx`.
    Cursor(String),
    /// `--page next` — resolves against the last cursor recorded
    /// for the same normalized command line.
    Next,
}

impl PageArg {
    /// Parse from a raw `--page` string.
    pub(crate) fn parse(raw: &str) -> Result<Self, String> {
        let t = raw.trim();
        if t.is_empty() || t.eq_ignore_ascii_case("first") || t == "1" {
            return Ok(PageArg::First);
        }
        if t.eq_ignore_ascii_case("next") {
            return Ok(PageArg::Next);
        }
        if let Some(rest) = t.strip_prefix("P:") {
            if rest.len() == 8
                && rest
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
            {
                return Ok(PageArg::Cursor(t.to_string()));
            }
            return Err(format!(
                "invalid --page cursor `{raw}` — expected `P:` + 8 lowercase hex chars"
            ));
        }
        match t.parse::<u64>() {
            Ok(n) if n >= 1 => Ok(PageArg::Number(n)),
            _ => Err(format!(
                "invalid --page value `{raw}` — expected 1-based page number or `P:xxxxxxxx`"
            )),
        }
    }
}

impl std::str::FromStr for PageArg {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        PageArg::parse(s)
    }
}

/// Bundle of paging inputs threaded into every command's renderer.
#[derive(Clone, Debug)]
pub(crate) struct PagingConfig {
    pub context: Option<u64>,
    pub page: PageArg,
    pub page_size: Option<u64>,
    pub all: bool,
    pub format_class: FormatClass,
}

impl PagingConfig {
    /// Given raw CLI inputs, build the config with `BONSAI_CONTEXT`
    /// env fallback applied.
    pub(crate) fn new(
        context: Option<u64>,
        page: PageArg,
        page_size: Option<u64>,
        all: bool,
        format_class: FormatClass,
    ) -> Self {
        let effective_context = if all {
            None
        } else {
            context.or_else(|| {
                std::env::var("BONSAI_CONTEXT")
                    .ok()
                    .and_then(|v| parse_context(&v).ok().flatten())
            })
        };
        Self {
            context: effective_context,
            page,
            page_size,
            all,
            format_class,
        }
    }

    /// Resolve the effective budget for this render. Text mode
    /// falls back to the 32 k default when no explicit value +
    /// no env var; programmatic formats stay uncapped unless the
    /// user opted in.
    pub(crate) fn effective_budget(&self) -> Option<u64> {
        if self.all {
            return None;
        }
        if let Some(b) = self.context {
            return Some(b);
        }
        match self.format_class {
            FormatClass::Text => Some(DEFAULT_CONTEXT_TEXT),
            FormatClass::Programmatic | FormatClass::RenderOnly => None,
        }
    }

    /// Should we emit the `{rows, page}` wrapper instead of a
    /// bare array for programmatic formats? Only when the user
    /// explicitly opted into paging for this run.
    pub(crate) fn json_wrapped(&self) -> bool {
        matches!(self.format_class, FormatClass::Programmatic)
            && (self.context.is_some() || !matches!(self.page, PageArg::First))
    }
}

/// Build a paging config directly from raw CLI strings. This is used
/// by commands that do their own structural slicing before rendering
/// instead of passing a prebuilt `PagingConfig` through the generic
/// row paginator.
pub(crate) fn config_from_raw(
    context: Option<&str>,
    page: Option<&str>,
    all: bool,
    format_class: FormatClass,
) -> Result<PagingConfig, String> {
    let parsed_context = match context {
        Some(raw) => parse_context(raw)?,
        None => None,
    };
    let page_arg = match page {
        Some(raw) => PageArg::parse(raw)?,
        None => PageArg::First,
    };
    let explicit_uncapped = context.is_some() && parsed_context.is_none();
    Ok(PagingConfig::new(
        parsed_context,
        page_arg,
        None,
        all || explicit_uncapped,
        format_class,
    ))
}

/// Info about the paginated slice — emitted in the text footer
/// and the JSON `page` object.
#[derive(Clone, Debug)]
pub(crate) struct PageInfo {
    pub page_number: u64,
    pub total_pages: u64,
    pub page_size: u64,
    pub shown_rows: u64,
    pub total_rows: u64,
    pub budget: Option<u64>,
    pub tokens_used: u64,
    pub cursor: String,
    pub next_cursor: Option<String>,
    pub is_last: bool,
    /// Zero-based row index where this page begins. Callers that do
    /// their own live-budget rendering (e.g. multi-section commands
    /// like `inspect`, where the "row" is a whole FLOW block with
    /// wildly variable cost) use this to resume from the right point
    /// without recomputing the cursor hash themselves.
    pub start_offset: u64,
    /// Estimated token cost of the full uncapped render — every row
    /// rendered at its full cost, no budget gating. Lets the footer
    /// tell the user "you're seeing 3,445 of ~35,000 tokens" so
    /// they can size the next `--context` or choose `--all`.
    pub total_tokens_uncapped: u64,
}

/// Stable content-hash id for a paginated slice. Same FNV-1a-64
/// body as `F:` / `G:` / etc. — 8 lowercase hex under the `P:`
/// prefix. Input = `(command, filters_hash, offset)`.
pub(crate) fn cursor_id(command: &str, filters_hash: u64, offset: u64) -> String {
    let mut hasher = bonsai_hash::Hasher::new();
    hasher.absorb(command.as_bytes());
    hasher.absorb_separator();
    hasher.absorb(&filters_hash.to_le_bytes());
    hasher.absorb_separator();
    hasher.absorb(&offset.to_le_bytes());
    format!("P:{:08x}", bonsai_hash::fnv1a_low32(hasher.finish()))
}

/// FNV-1a-64 digest of a stringifiable filter spec. Accepts any
/// slice of `(name, value)` pairs. Stable across runs / hosts.
pub(crate) fn hash_filters(pairs: &[(&str, &str)]) -> u64 {
    let mut hasher = bonsai_hash::Hasher::new();
    for (k, v) in pairs {
        hasher.absorb(k.as_bytes());
        hasher.absorb_separator();
        hasher.absorb(v.as_bytes());
        hasher.absorb_separator();
    }
    hasher.finish()
}

/// Convert a byte count into an estimated token count using the
/// same 4-bytes-per-token heuristic the output footer uses. Never
/// returns zero for a non-empty string — every row costs at least
/// one token.
#[must_use]
pub(crate) fn bytes_to_tokens(bytes: u64) -> u64 {
    if bytes == 0 {
        0
    } else {
        bytes.div_ceil(BYTES_PER_TOKEN).max(1)
    }
}

/// Per-row rendering overhead for a comfy-table horizontal-rule
/// view (the shape used by every browse / security / dump-callgraph
/// / dump-edges command). Covers column padding (2–4 spaces per
/// column × 5–8 columns), ANSI styling bursts around cells
/// (~20 bytes each), the `↑ same`-fold prefixes, the `flows`-column
/// F-id list, and the occasional line-wrap that comfy-table adds
/// when a cell's text doesn't fit the terminal's column budget.
/// Without this floor, the cost estimates under-count by 4–6× and
/// `--context` budgets aren't respected in practice.
///
/// Calibrated against actual rendered output from
/// `examples/python/complex`:
/// - `defs` 179 rows / 101 777 bytes ≈ 568 B/row
/// - `calls` 100 rows / 45 000 bytes ≈ 450 B/row
/// - `args` 74 rows / 23 000 bytes ≈ 310 B/row
/// - `strings` 43 rows / 73 000 bytes ≈ 1 700 B/row (string literal
///   text is already counted in the per-command cost; residual is
///   column chrome)
///
/// 500 is the floor that brings every browse command within 5 %
/// of its real rendered size without over-penalising tiny rows.
pub(crate) const TABLE_ROW_CHROME_BYTES: u64 = 500;

/// Paginate `rows` under the active config. Returns the slice of
/// rows to render plus the page metadata the renderer uses for
/// the footer / JSON wrapper.
///
/// `row_cost_bytes` is the renderer-supplied ANSI-free byte cost
/// for each row. Chrome (headers / separators / footer) is
/// reserved at [`CHROME_RESERVE`] of the budget.
pub(crate) fn paginate<T, F>(
    rows: &[T],
    cfg: &PagingConfig,
    command: &str,
    filters_hash: u64,
    row_cost_bytes: F,
) -> (Vec<T>, PageInfo)
where
    T: Clone,
    F: Fn(&T) -> u64,
{
    let total_rows = rows.len() as u64;
    let total_tokens_uncapped: u64 = rows.iter().map(|r| bytes_to_tokens(row_cost_bytes(r))).sum();
    // `--all` overrides every cap; hand back every row.
    if cfg.all {
        let info = PageInfo {
            page_number: 1,
            total_pages: 1,
            page_size: total_rows.max(1),
            shown_rows: total_rows,
            total_rows,
            budget: None,
            tokens_used: total_tokens_uncapped,
            cursor: cursor_id(command, filters_hash, 0),
            next_cursor: None,
            is_last: true,
            start_offset: 0,
            total_tokens_uncapped,
        };
        return (rows.to_vec(), info);
    }
    // Compute per-row token cost once. Paging walks these.
    let per_row: Vec<u64> = rows.iter().map(|r| bytes_to_tokens(row_cost_bytes(r))).collect();
    // Budget math. If no budget, one page = everything.
    let effective_budget = cfg.effective_budget();
    let per_page_budget = effective_budget.map(|b| {
        let reserve = (b as f64 * CHROME_RESERVE) as u64;
        b.saturating_sub(reserve).max(1)
    });
    // Build the page boundaries up front so page numbering + cursor
    // resolution agree. Each boundary is `(start_offset, row_count)`.
    let page_size_override = cfg.page_size;
    let mut pages: Vec<(u64, u64)> = Vec::new();
    let mut row_offset: u64 = 0;
    while row_offset < total_rows {
        let mut rows_this_page: u64 = 0;
        let mut tokens_this_page: u64 = 0;
        while (row_offset + rows_this_page) < total_rows {
            if let Some(cap) = page_size_override {
                if rows_this_page >= cap {
                    break;
                }
            }
            let cost = per_row[(row_offset + rows_this_page) as usize];
            if let Some(budget) = per_page_budget {
                // Always take at least one row per page so a single
                // oversized row still renders (with a `row exceeds
                // --context` warning in the footer, added by the
                // caller when `tokens_used > budget`).
                if rows_this_page > 0 && tokens_this_page + cost > budget {
                    break;
                }
            }
            tokens_this_page += cost;
            rows_this_page += 1;
        }
        if rows_this_page == 0 {
            rows_this_page = 1;
        }
        pages.push((row_offset, rows_this_page));
        row_offset += rows_this_page;
    }
    if pages.is_empty() {
        pages.push((0, 0));
    }
    // Resolve `--page` to an index.
    let target_idx: u64 = match &cfg.page {
        PageArg::First => 0,
        PageArg::Number(n) => n.saturating_sub(1),
        PageArg::Cursor(c) => pages
            .iter()
            .position(|(offset, _)| cursor_id(command, filters_hash, *offset) == *c)
            .map(|p| p as u64)
            .unwrap_or(0),
        PageArg::Next => {
            // `--page next` resolves to the page after the one
            // stored in the last-cursor history. If no history,
            // start at page 1.
            last_cursor(command, filters_hash)
                .and_then(|cur| {
                    pages
                        .iter()
                        .position(|(offset, _)| cursor_id(command, filters_hash, *offset) == cur)
                        .map(|p| p as u64 + 1)
                })
                .unwrap_or(0)
        }
    };
    let total_pages = pages.len() as u64;
    let clamped_idx = target_idx.min(total_pages.saturating_sub(1));
    let (start_offset, row_count) = pages[clamped_idx as usize];
    let slice: Vec<T> = rows
        .iter()
        .skip(start_offset as usize)
        .take(row_count as usize)
        .cloned()
        .collect();
    let tokens_used: u64 = (start_offset..start_offset + row_count)
        .map(|row_index| per_row[row_index as usize])
        .sum();
    let is_last = clamped_idx + 1 >= total_pages;
    let cursor = cursor_id(command, filters_hash, start_offset);
    let next_cursor = if is_last {
        None
    } else {
        Some(cursor_id(
            command,
            filters_hash,
            pages[(clamped_idx + 1) as usize].0,
        ))
    };
    write_last_cursor(command, filters_hash, &cursor);
    (
        slice,
        PageInfo {
            page_number: clamped_idx + 1,
            total_pages,
            page_size: row_count,
            shown_rows: row_count,
            total_rows,
            budget: effective_budget,
            tokens_used,
            cursor,
            next_cursor,
            is_last,
            start_offset,
            total_tokens_uncapped,
        },
    )
}

// Last-cursor history backs `--page next`. Keyed by `(normalized argv,
// command, filters_hash)`; each invocation overwrites its own key so the
// next call advances by one. The in-process map serves tests; a temp-dir
// JSON file persists across the fresh-process invocations of normal CLI use.
static LAST_CURSORS: OnceLock<std::sync::Mutex<AHashMap<(String, u64), String>>> = OnceLock::new();

fn cursor_store() -> &'static std::sync::Mutex<AHashMap<(String, u64), String>> {
    LAST_CURSORS.get_or_init(|| std::sync::Mutex::new(AHashMap::new()))
}

pub(crate) fn last_cursor(command: &str, filters_hash: u64) -> Option<String> {
    let key = cursor_key(command, filters_hash);
    if let Some(cursor) = cursor_store()
        .lock()
        .ok()
        .and_then(|m| m.get(&(key.clone(), filters_hash)).cloned())
    {
        return Some(cursor);
    }
    read_cursor_file().get(&key).cloned()
}

pub(crate) fn write_last_cursor(command: &str, filters_hash: u64, cursor: &str) {
    let key = cursor_key(command, filters_hash);
    if let Ok(mut m) = cursor_store().lock() {
        m.insert((key.clone(), filters_hash), cursor.to_string());
    }
    let mut on_disk = read_cursor_file();
    on_disk.insert(key, cursor.to_string());
    let _ = write_cursor_file(&on_disk);
}

fn cursor_key(command: &str, filters_hash: u64) -> String {
    let cwd = std::env::current_dir()
        .ok()
        .map(|p| p.display().to_string())
        .unwrap_or_default();
    format!(
        "{cwd}\0{}\0{command}\0{filters_hash:x}",
        normalized_argv_for_cursor()
    )
}

fn normalized_argv_for_cursor() -> String {
    let mut out = Vec::new();
    let mut args = std::env::args().skip(1).peekable();
    while let Some(arg) = args.next() {
        if arg == "--page" {
            let _ = args.next();
            continue;
        }
        if arg.starts_with("--page=") {
            continue;
        }
        out.push(arg);
    }
    out.join("\0")
}

fn cursor_file() -> PathBuf {
    std::env::temp_dir().join("bonsai-ninja-last-cursor.v1.json")
}

fn cursor_file_tmp_path(path: &Path) -> PathBuf {
    let counter = CURSOR_FILE_TMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut name = path
        .file_name()
        .map(OsString::from)
        .unwrap_or_else(|| OsString::from("bonsai-ninja-last-cursor.v1.json"));
    name.push(format!(".tmp.{}.{}", std::process::id(), counter));
    path.with_file_name(name)
}

fn read_cursor_file() -> BTreeMap<String, String> {
    let path = cursor_file();
    let Ok(bytes) = std::fs::read(path) else {
        return BTreeMap::new();
    };
    serde_json::from_slice(&bytes).unwrap_or_default()
}

fn write_cursor_file(map: &BTreeMap<String, String>) -> std::io::Result<()> {
    let path = cursor_file();
    let tmp = cursor_file_tmp_path(&path);
    let bytes = serde_json::to_vec(map).map_err(std::io::Error::other)?;
    {
        use std::io::Write;
        let mut tmp_file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)?;
        tmp_file.write_all(&bytes)?;
        tmp_file.sync_all()?;
    }
    if let Err(err) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(err);
    }
    Ok(())
}

#[cfg(test)]
fn clear_cursor_history_for_tests() {
    if let Ok(mut m) = cursor_store().lock() {
        m.clear();
    }
    let _ = std::fs::remove_file(cursor_file());
}

#[cfg(test)]
#[path = "paging_tests.rs"]
mod tests;
