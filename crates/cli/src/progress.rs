//! Progress-bar helpers for long-running CLI commands.
//!
//! Bars render to stderr (keeps `--format json` stdout clean) and
//! become a no-op when stderr isn't a TTY, `--no-progress` is set,
//! or `NO_PROGRESS` is present. `--no-color` / `NO_COLOR` keep bars
//! visible but render them without ANSI colors.

use indicatif::{ProgressBar, ProgressDrawTarget, ProgressStyle};
use std::io::IsTerminal;
use std::sync::OnceLock;

/// Global toggle backing `--no-progress`. Set once at CLI startup
/// from the flag or the `NO_PROGRESS` env var; every
/// [`progress_bar`] call reads it.
static NO_PROGRESS: OnceLock<bool> = OnceLock::new();
static NO_COLOR_PROGRESS: OnceLock<bool> = OnceLock::new();

/// Install the `--no-progress` toggle. Called once from the
/// top-level CLI dispatch before any command runs.
pub(crate) fn set_no_progress(disabled: bool) {
    let _ = NO_PROGRESS.set(disabled);
}

/// Install the `--no-color` toggle for progress styling. Progress
/// visibility is controlled separately by [`set_no_progress`].
pub(crate) fn set_no_color(disabled: bool) {
    let _ = NO_COLOR_PROGRESS.set(disabled);
}

/// `true` when the CLI has been told (via flag, env, or TTY
/// detection) that it should not draw progress bars.
#[must_use]
pub(crate) fn is_disabled() -> bool {
    if *NO_PROGRESS.get().unwrap_or(&false) {
        return true;
    }
    if std::env::var("NO_PROGRESS").is_ok() {
        return true;
    }
    !std::io::stderr().is_terminal()
}

#[must_use]
pub(crate) fn is_explicitly_disabled() -> bool {
    *NO_PROGRESS.get().unwrap_or(&false) || std::env::var("NO_PROGRESS").is_ok()
}

fn color_disabled() -> bool {
    *NO_COLOR_PROGRESS.get().unwrap_or(&false) || std::env::var("NO_COLOR").is_ok()
}

#[must_use]
pub(crate) fn debug_category_enabled(category: &str) -> bool {
    std::env::var("BONSAI_DEBUG").ok().is_some_and(|raw| {
        raw.split(',')
            .map(str::trim)
            .any(|part| part == category || part == "*" || part == "all")
    })
}

/// Whether the per-command workspace footer (cloc/LLM-style
/// summary: files, lines, tokens, defs, calls, imports, top
/// languages) should render. Reuses the progress-bar gating rules:
/// stderr TTY, no mute env/flag set. Means CI runs, `--format json`
/// piped consumers, and explicitly-muted shells all stay clean;
/// interactive terminals get the footer for free.
#[must_use]
pub(crate) fn is_footer_enabled() -> bool {
    !is_disabled()
}

/// Build a progress bar for a known total. Returns
/// [`ProgressBar::hidden`] when bars are disabled — safe to call
/// unconditionally, then invoke `inc(1)` in the hot loop; the
/// hidden variant is a fast no-op.
#[must_use]
pub(crate) fn progress_bar(label: &str, total: u64) -> ProgressBar {
    if is_disabled() {
        return ProgressBar::hidden();
    }
    let bar = ProgressBar::with_draw_target(Some(total), ProgressDrawTarget::stderr());
    let template = if color_disabled() {
        "  {msg:<24} [{bar:30}] {pos}/{len} ({eta})"
    } else {
        "  {msg:<24} [{bar:30.cyan/blue}] {pos}/{len} ({eta})"
    };
    if let Ok(style) = ProgressStyle::with_template(template) {
        bar.set_style(style.progress_chars("━━╸ "));
    }
    bar.set_message(label.to_string());
    bar
}

/// Build a spinner for operations without a known total count
/// (e.g. workspace ingestion before the file count is known).
/// Falls back to [`ProgressBar::hidden`] when bars are disabled.
#[must_use]
pub(crate) fn spinner(label: &str) -> ProgressBar {
    if is_disabled() {
        return ProgressBar::hidden();
    }
    let spin = ProgressBar::with_draw_target(None, ProgressDrawTarget::stderr());
    let template = if color_disabled() {
        "  {spinner} {msg}"
    } else {
        "  {spinner:.cyan} {msg}"
    };
    if let Ok(style) = ProgressStyle::with_template(template) {
        spin.set_style(style.tick_chars("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏ "));
    }
    spin.set_message(label.to_string());
    spin.enable_steady_tick(std::time::Duration::from_millis(120));
    spin
}

/// Scoped spinner for command stages whose duration is not known up
/// front. The bar is cleared both on explicit [`Self::finish`] and on drop,
/// so early returns do not leave terminal chrome behind.
pub(crate) struct ScopedSpinner {
    bar: Option<ProgressBar>,
}

impl ScopedSpinner {
    #[must_use]
    pub(crate) fn new(label: &str) -> Self {
        Self {
            bar: Some(spinner(label)),
        }
    }

    pub(crate) fn finish(mut self) {
        if let Some(bar) = self.bar.take() {
            bar.finish_and_clear();
        }
    }
}

impl Drop for ScopedSpinner {
    fn drop(&mut self) {
        if let Some(bar) = self.bar.take() {
            bar.finish_and_clear();
        }
    }
}
