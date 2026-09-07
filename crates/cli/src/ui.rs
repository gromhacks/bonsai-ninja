//! CLI presentation helpers: colors, tables, syntax-highlighted source.
//!
//! A single `Ui` handle is threaded into every text renderer. When stdout
//! is not a TTY, or the user passed `--no-color`, or `NO_COLOR` is set in
//! the environment, all styling functions become identity passes so
//! downstream pipes stay clean.
//!
//! The UI splits presentation into two layers:
//!
//! * **Chrome** — borders, headers, names, paths, kind tags. Driven by a
//!   [`Theme`]'s [`ChromePalette`].
//! * **Syntax** — source-code snippets inside refs/inspect. Driven by the
//!   same Tree-sitter grammars and queries as the compiler-style engine.

use crate::syntax_highlight::syntax_highlight_cache;
use crate::theme::{ChromePalette, Theme};
use comfy_table::{presets::NOTHING, Cell, ColumnConstraint, ContentArrangement, LineStyle, Table, Width};
use owo_colors::OwoColorize;
use std::io::IsTerminal;

pub(crate) struct Ui {
    colors: bool,
    palette: ChromePalette,
    theme: Theme,
}

/// Dense inventories become labeled records when the terminal cannot afford
/// readable columns. This changes layout only: every original cell survives.
pub(crate) struct UiTable {
    table: Table,
    pinned: Vec<usize>,
}

impl std::ops::Deref for UiTable {
    type Target = Table;

    fn deref(&self) -> &Self::Target {
        &self.table
    }
}

impl std::ops::DerefMut for UiTable {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.table
    }
}

impl std::fmt::Display for UiTable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Some(header) = self.table.header() else {
            return std::fmt::Display::fmt(&self.table, f);
        };
        let columns = header.cell_iter().count();
        let width = self.table.width().unwrap_or(140);
        if columns < 4
            || usize::from(width) / columns >= 22
            || self.table.row_count() == 0
            || self
                .table
                .row_iter()
                .any(|row| row.cell_iter().count() != columns)
        {
            return write!(f, "{}", self.table.trim_fmt());
        }
        for (row_index, row) in self.table.row_iter().enumerate() {
            if row_index > 0 {
                writeln!(f)?;
            }
            for (index, (label, value)) in header.cell_iter().zip(row.cell_iter()).enumerate() {
                let mut field = Table::new();
                field.load_style(NOTHING);
                field.set_content_arrangement(ContentArrangement::Dynamic);
                field.set_width(width);
                field.add_row(vec![label.clone(), value.clone()]);
                field.set_constraints(vec![
                    ColumnConstraint::Absolute(Width::Fixed(18)),
                    if self.pinned.contains(&index) {
                        // Copyable rule/stable IDs must never be split just to
                        // fit a terminal. Only their line may exceed its width.
                        ColumnConstraint::ContentWidth
                    } else {
                        ColumnConstraint::LowerBoundary(Width::Fixed(1))
                    },
                ]);
                writeln!(f, "{}", field.trim_fmt())?;
            }
        }
        Ok(())
    }
}

impl Ui {
    /// Rendered pages are reusable only for the same effective display, even
    /// when argv is unchanged (TTY, NO_COLOR, BONSAI_THEME, resize/COLUMNS).
    pub(crate) fn render_identity(&self) -> String {
        format!("{:?}:{}:{:?}", self.theme, self.colors, terminal_width())
    }

    /// Build a UI honoring `--no-color`, `NO_COLOR`, and stdout-is-TTY.
    /// The theme selection comes from `--theme` / `BONSAI_THEME` (default:
    /// `moss` — the bonsai-ninja house palette).
    #[must_use]
    pub(crate) fn new(no_color: bool, theme: Theme) -> Self {
        let nc_env = std::env::var_os("NO_COLOR").is_some();
        let tty = std::io::stdout().is_terminal();
        let colors = !no_color && !nc_env && tty;
        Self {
            colors,
            palette: theme.palette(),
            theme,
        }
    }

    /// Applies a palette style to `text`, but only when color is on.
    fn apply(&self, text: &str, style: &owo_colors::Style) -> String {
        if self.colors {
            text.style(*style).to_string()
        } else {
            text.to_string()
        }
    }

    // --- chrome styles ---------------------------------------------------

    pub(crate) fn heading(&self, text: &str) -> String {
        if self.colors {
            format!("\n{}", text.style(self.palette.header).underline())
        } else {
            format!("\n{text}")
        }
    }

    pub(crate) fn label(&self, text: &str) -> String {
        self.apply(text, &self.palette.accent)
    }

    pub(crate) fn path(&self, text: &str) -> String {
        self.apply(text, &self.palette.path)
    }

    pub(crate) fn loc(&self, text: &str) -> String {
        self.apply(text, &self.palette.dim)
    }

    pub(crate) fn kind(&self, text: &str) -> String {
        self.apply(text, &self.palette.kind)
    }

    pub(crate) fn name(&self, text: &str) -> String {
        self.apply(text, &self.palette.name)
    }

    pub(crate) fn annotation(&self, text: &str) -> String {
        self.apply(text, &self.palette.accent)
    }

    pub(crate) fn step(&self, text: &str) -> String {
        self.apply(text, &self.palette.accent)
    }

    pub(crate) fn dim(&self, text: &str) -> String {
        self.apply(text, &self.palette.dim)
    }

    pub(crate) fn warn(&self, text: &str) -> String {
        self.apply(text, &self.palette.warn)
    }

    pub(crate) fn severity(&self, text: &str) -> String {
        match crate::theme::severity_color(text) {
            Some(color) => self.apply(text, &owo_colors::Style::new().color(color).bold()),
            None => self.dim(text),
        }
    }

    /// A consistent, source-independent title for syntax inventory pages.
    pub(crate) fn result_heading(&self, command: &str, count: u64, singular: &str, plural: &str) -> String {
        format!(
            "{} — {} {}",
            self.label(command),
            self.name(&crate::footer::format_count(count as usize)),
            if count == 1 { singular } else { plural },
        )
    }

    pub(crate) fn wrapped_warn_labeled_lines(&self, label: &str, text: &str) -> Vec<String> {
        self.wrapped_labeled_lines(label, text, TextTone::Warn)
    }

    pub(crate) fn wrapped_annotation_prefixed_lines(
        &self,
        raw_first_prefix: &str,
        styled_first_prefix: &str,
        next_prefix: &str,
        text: &str,
    ) -> Vec<String> {
        self.wrapped_prefixed_lines(
            raw_first_prefix,
            styled_first_prefix,
            next_prefix,
            text,
            TextTone::Annotation,
        )
    }

    pub(crate) fn wrapped_dim_prefixed_lines(
        &self,
        raw_first_prefix: &str,
        styled_first_prefix: &str,
        next_prefix: &str,
        text: &str,
    ) -> Vec<String> {
        self.wrapped_prefixed_lines(
            raw_first_prefix,
            styled_first_prefix,
            next_prefix,
            text,
            TextTone::Dim,
        )
    }

    fn wrapped_labeled_lines(&self, label: &str, text: &str, tone: TextTone) -> Vec<String> {
        let first_prefix_raw = format!("  {label} ");
        let next_prefix = " ".repeat(first_prefix_raw.len());
        let first_prefix = format!("  {} ", self.label(label));
        self.wrapped_prefixed_lines(&first_prefix_raw, &first_prefix, &next_prefix, text, tone)
    }

    fn wrapped_prefixed_lines(
        &self,
        raw_first_prefix: &str,
        styled_first_prefix: &str,
        next_prefix: &str,
        text: &str,
        tone: TextTone,
    ) -> Vec<String> {
        let width = usize::from(terminal_width().unwrap_or(120));
        wrap_words(text, width.saturating_sub(raw_first_prefix.len()).max(24))
            .into_iter()
            .enumerate()
            .map(|(idx, part)| {
                let styled = self.apply_tone(&part, tone);
                if idx == 0 {
                    format!("{styled_first_prefix}{styled}")
                } else {
                    format!("{next_prefix}{styled}")
                }
            })
            .collect()
    }

    fn apply_tone(&self, text: &str, tone: TextTone) -> String {
        match tone {
            TextTone::Annotation => self.annotation(text),
            TextTone::Dim => self.dim(text),
            TextTone::Warn => self.warn(text),
        }
    }

    pub(crate) fn ruler(&self, ch: char, width: usize) -> String {
        let width = terminal_width().map_or(width, |available| width.min(usize::from(available)));
        let line: String = std::iter::repeat_n(ch, width).collect();
        self.apply(&line, &self.palette.border)
    }

    // --- tables ----------------------------------------------------------

    /// Make a horizontal-rule table (header underline + bottom border
    /// only, no per-row separators). Cleaner than the full grid for
    /// browse listings while still giving a visible header break.
    #[must_use]
    pub(crate) fn table(&self, headers: &[&str]) -> UiTable {
        let mut t = Table::new();
        // Minimal chrome: header underline + bottom rule, no per-row
        // divider lines. We also force the header/bottom *intersections*
        // to the same dash character so the rule prints as one
        // continuous line instead of gapping at column boundaries.
        t.load_style(
            NOTHING
                .header_separator(LineStyle::new('─', '─', '─', '─'))
                .bottom_border(LineStyle::new('─', '─', '─', '─')),
        );
        t.set_content_arrangement(ContentArrangement::Dynamic);
        t.set_width(terminal_width().unwrap_or(140));
        let cells: Vec<Cell> = headers
            .iter()
            .map(|h| Cell::new(self.apply(h, &self.palette.header)))
            .collect();
        t.set_header(cells);
        if let Some(flow_col) = headers.iter().position(|h| *h == "flows") {
            let mut constraints = vec![ColumnConstraint::LowerBoundary(Width::Fixed(1)); headers.len()];
            constraints[flow_col] = ColumnConstraint::Absolute(Width::Fixed(8));
            t.set_constraints(constraints);
        }
        UiTable {
            table: t,
            pinned: Vec::new(),
        }
    }

    /// A [`Self::table`] whose `pinned` columns always render at their
    /// content width. Identifier columns (rule ids, stable ids) must never
    /// be wrapped or truncated to fit a narrow terminal: a cut id cannot be
    /// copied back into `--rule` / `show`, so prose columns absorb the
    /// width pressure instead.
    pub(crate) fn table_pinned(&self, headers: &[&str], pinned: &[&str]) -> UiTable {
        let mut t = self.table(headers);
        let constraints: Vec<ColumnConstraint> = headers
            .iter()
            .map(|header| {
                if pinned.contains(header) {
                    ColumnConstraint::ContentWidth
                } else if *header == "flows" {
                    ColumnConstraint::Absolute(Width::Fixed(8))
                } else {
                    ColumnConstraint::LowerBoundary(Width::Fixed(1))
                }
            })
            .collect();
        t.set_constraints(constraints);
        t.pinned = headers
            .iter()
            .enumerate()
            .filter_map(|(index, header)| pinned.contains(header).then_some(index))
            .collect();
        t
    }

    // --- syntax highlighting --------------------------------------------

    /// Highlight a full code block using compiler syntax facts.
    #[must_use]
    pub(crate) fn highlight(&self, code: &str, extension: &str) -> String {
        if !self.colors {
            return code.to_string();
        }
        syntax_highlight_cache().highlight(code, extension, self.theme)
    }

    /// Highlight a short (usually one-line) snippet and trim trailing
    /// whitespace. Guaranteed to not contain line terminators so it sits
    /// nicely in a table cell.
    #[must_use]
    /// Colorize a YAML block line by line: comments dim, list markers and
    /// scalar literals as annotations, keys as names, quoted strings as
    /// kinds. Block scalars (`code: |`) are source in the rule's language and
    /// are highlighted with that language's grammar. Indentation is kept so
    /// the block stays valid YAML when copied.
    pub(crate) fn yaml_block(&self, text: &str, language: &str) -> Vec<String> {
        let extension = crate::syntax_highlight::extension_for_language(language);
        let mut out = Vec::new();
        let mut block_scalar_indent: Option<usize> = None;
        for raw in text.lines() {
            let line = raw.trim_end_matches('\r');
            let indent = line.len() - line.trim_start().len();
            if let Some(scalar_indent) = block_scalar_indent {
                if line.trim().is_empty() || indent > scalar_indent {
                    let body = &line[indent.min(line.len())..];
                    let painted = match extension {
                        Some(ext) if self.colors => self.snippet(body, ext),
                        _ => body.to_string(),
                    };
                    out.push(format!("{}{painted}", " ".repeat(indent)));
                    continue;
                }
                block_scalar_indent = None;
            }
            if !self.colors {
                out.push(line.to_string());
                continue;
            }
            let trimmed = line.trim_start();
            if trimmed.starts_with('#') {
                out.push(format!("{}{}", " ".repeat(indent), self.dim(trimmed)));
                continue;
            }
            let (marker, rest) = match trimmed.strip_prefix("- ") {
                Some(rest) => (self.annotation("- "), rest),
                None => (String::new(), trimmed),
            };
            let painted_rest = match split_yaml_key(rest) {
                Some((key, value)) => {
                    let value = value.trim_start();
                    if value == "|" || value == "|-" || value == ">" || value == ">-" {
                        block_scalar_indent = Some(indent);
                    }
                    format!("{}: {}", self.name(key), self.yaml_scalar(value))
                }
                None => self.yaml_scalar(rest),
            };
            out.push(format!("{}{marker}{painted_rest}", " ".repeat(indent)));
        }
        out
    }

    fn yaml_scalar(&self, value: &str) -> String {
        if value.is_empty() {
            return String::new();
        }
        let (body, comment) = split_yaml_comment(value);
        let painted = if body.starts_with('"') || body.starts_with('\'') {
            self.kind(body)
        } else if body == "|" || body == "|-" || body == ">" || body == ">-" {
            self.dim(body)
        } else if body.starts_with('[') {
            let inner = body.trim_start_matches('[').trim_end_matches(']');
            let items: Vec<String> = inner.split(',').map(|item| self.kind(item.trim())).collect();
            format!("[{}]", items.join(", "))
        } else if matches!(body, "true" | "false" | "null" | "~") || body.parse::<f64>().is_ok() {
            self.annotation(body)
        } else {
            body.to_string()
        };
        match comment {
            Some(comment) => format!("{painted} {}", self.dim(comment)),
            None => painted,
        }
    }

    pub(crate) fn snippet(&self, code: &str, extension: &str) -> String {
        let trimmed = code.trim_end_matches(['\n', '\r']).trim();
        if !self.colors {
            return trimmed.to_string();
        }
        let highlighted = syntax_highlight_cache().highlight(trimmed, extension, self.theme);
        // Strip the trailing reset so it doesn't leak past the cell.
        highlighted.trim_end_matches("\x1b[0m").trim_end().to_string()
    }
}

/// Split `key: value` at the first unquoted `: ` (or trailing `:`).
fn split_yaml_key(line: &str) -> Option<(&str, &str)> {
    let mut quote: Option<char> = None;
    for (index, ch) in line.char_indices() {
        match (quote, ch) {
            (Some(open), c) if c == open => quote = None,
            (Some(_), _) => {}
            (None, '"' | '\'') => quote = Some(ch),
            (None, ':') => {
                let rest = &line[index + 1..];
                if rest.is_empty() || rest.starts_with(' ') {
                    let key = &line[..index];
                    if key.is_empty() || key.starts_with('[') || key.starts_with('{') {
                        return None;
                    }
                    return Some((key, rest));
                }
            }
            _ => {}
        }
    }
    None
}

/// Split a scalar from a trailing ` #comment` outside quotes.
fn split_yaml_comment(value: &str) -> (&str, Option<&str>) {
    let mut quote: Option<char> = None;
    let mut previous = ' ';
    for (index, ch) in value.char_indices() {
        match (quote, ch) {
            (Some(open), c) if c == open => quote = None,
            (Some(_), _) => {}
            (None, '"' | '\'') => quote = Some(ch),
            (None, '#') if previous == ' ' => {
                return (value[..index].trim_end(), Some(&value[index..]));
            }
            _ => {}
        }
        previous = ch;
    }
    (value, None)
}

#[derive(Clone, Copy)]
enum TextTone {
    Annotation,
    Dim,
    Warn,
}

fn wrap_words(text: &str, width: usize) -> Vec<String> {
    let width = width.max(24);
    let mut lines = Vec::new();
    let mut current = String::new();
    for word in text.split_whitespace() {
        if current.is_empty() {
            current.push_str(word);
        } else if current.len().saturating_add(1).saturating_add(word.len()) <= width {
            current.push(' ');
            current.push_str(word);
        } else {
            lines.push(current);
            current = word.to_string();
        }
    }
    if !current.is_empty() {
        lines.push(current);
    }
    if lines.is_empty() {
        lines.push(String::new());
    }
    lines
}

/// Best-effort terminal-width probe. Returns `None` when the size isn't
/// discoverable so callers can fall back to a fixed default.
fn terminal_width() -> Option<u16> {
    std::env::var("COLUMNS")
        .ok()
        .and_then(|s| s.parse::<u16>().ok())
        .filter(|w| *w >= 40)
        .or_else(|| Table::new().width().filter(|w| *w >= 40))
}

/// Best-effort extension extraction from a workspace path.
#[must_use]
pub(crate) fn extension_for(path: &str) -> &str {
    std::path::Path::new(path)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
}

#[cfg(test)]
#[path = "ui_tests.rs"]
mod tests;
