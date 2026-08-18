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

impl Ui {
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

    pub(crate) fn wrapped_bullet_lines(&self, bullet: &str, text: &str) -> Vec<String> {
        let first_prefix = format!("    {bullet} ");
        let next_prefix = " ".repeat(first_prefix.len());
        self.wrapped_dim_prefixed_lines(&first_prefix, &self.dim(&first_prefix), &next_prefix, text)
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
        let line: String = std::iter::repeat_n(ch, width).collect();
        self.apply(&line, &self.palette.border)
    }

    // --- tables ----------------------------------------------------------

    /// Make a horizontal-rule table (header underline + bottom border
    /// only, no per-row separators). Cleaner than the full grid for
    /// browse listings while still giving a visible header break.
    #[must_use]
    pub(crate) fn table(&self, headers: &[&str]) -> Table {
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
