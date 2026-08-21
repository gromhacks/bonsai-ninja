//! Progress-bar helpers for long-running CLI commands.
//!
//! Bars render to stderr (keeps `--format json` stdout clean) and
//! become a no-op when stderr isn't a TTY, `--no-progress` is set,
//! or `NO_PROGRESS` is present. `--no-color` / `NO_COLOR` keep bars
//! visible but render them without ANSI colors.

use indicatif::{ProgressBar, ProgressDrawTarget, ProgressStyle};
use std::io::IsTerminal;
use std::sync::{Mutex, OnceLock};

const PLAIN_BAR_TEMPLATE: &str =
    "  {msg:<24} [{bar:20}] {pos}/{len} · {percent:>3}% · {per_sec:1} · ETA {eta} · {elapsed_precise}";
const COLOR_BAR_TEMPLATE: &str = "  {msg:<24} [{bar:20.cyan/blue}] {pos}/{len} · {percent:>3}% · {per_sec:1} · ETA {eta} · {elapsed_precise}";
const PLAIN_SPINNER_TEMPLATE: &str = "  {spinner} {msg} · {elapsed_precise}";
const COLOR_SPINNER_TEMPLATE: &str = "  {spinner:.cyan} {msg} · {elapsed_precise}";
const PLAIN_COUNTED_SPINNER_TEMPLATE: &str = "  {spinner} {msg} · {pos} completed · {elapsed_precise}";
const COLOR_COUNTED_SPINNER_TEMPLATE: &str = "  {spinner:.cyan} {msg} · {pos} completed · {elapsed_precise}";

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

#[must_use]
pub(crate) fn is_color_disabled() -> bool {
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
    let template = if is_color_disabled() {
        PLAIN_BAR_TEMPLATE
    } else {
        COLOR_BAR_TEMPLATE
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
    let template = if is_color_disabled() {
        PLAIN_SPINNER_TEMPLATE
    } else {
        COLOR_SPINNER_TEMPLATE
    };
    if let Ok(style) = ProgressStyle::with_template(template) {
        spin.set_style(style.tick_chars("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏ "));
    }
    spin.set_message(label.to_string());
    spin.enable_steady_tick(std::time::Duration::from_millis(120));
    spin
}

/// Switch an indeterminate phase to an exact completed-unit counter after its
/// first observable unit. The total remains unknown, so this deliberately
/// omits percentage and ETA while preserving the spinner's original clock.
pub(crate) fn show_spinner_count(bar: &ProgressBar) {
    let template = if is_color_disabled() {
        PLAIN_COUNTED_SPINNER_TEMPLATE
    } else {
        COLOR_COUNTED_SPINNER_TEMPLATE
    };
    if let Ok(style) = ProgressStyle::with_template(template) {
        bar.set_style(style.tick_chars("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏ "));
    }
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

/// Replaceable progress phase for pipelines that discover an exact work-unit
/// total after a short setup step, or transition from counted compiler work
/// to an indivisible persistence step.
pub(crate) struct PhaseProgress {
    bar: Mutex<Option<ProgressBar>>,
}

impl PhaseProgress {
    #[must_use]
    pub(crate) fn spinner(label: &str) -> Self {
        Self {
            bar: Mutex::new(Some(spinner(label))),
        }
    }

    pub(crate) fn start_bar(&self, label: &str, total: u64) {
        self.replace(progress_bar(label, total));
    }

    pub(crate) fn start_spinner(&self, label: &str) {
        self.replace(spinner(label));
    }

    pub(crate) fn inc(&self, delta: u64) {
        if let Some(bar) = self
            .bar
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
        {
            bar.inc(delta);
        }
    }

    pub(crate) fn finish(&self) {
        if let Some(bar) = self
            .bar
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
        {
            bar.finish_and_clear();
        }
    }

    fn replace(&self, next: ProgressBar) {
        let mut slot = self.bar.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(current) = slot.replace(next) {
            current.finish_and_clear();
        }
    }
}

impl Drop for PhaseProgress {
    fn drop(&mut self) {
        let slot = self
            .bar
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(bar) = slot.take() {
            bar.finish_and_clear();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn determinate_progress_exposes_completion_rate_eta_and_elapsed_time() {
        for template in [PLAIN_BAR_TEMPLATE, COLOR_BAR_TEMPLATE] {
            for metric in [
                "{pos}",
                "{len}",
                "{percent:>3}",
                "{per_sec:1}",
                "{eta}",
                "{elapsed_precise}",
            ] {
                assert!(template.contains(metric), "missing {metric} in {template}");
            }
        }
    }

    #[test]
    fn indeterminate_progress_never_implies_a_percentage_but_shows_elapsed_time() {
        for template in [
            PLAIN_SPINNER_TEMPLATE,
            COLOR_SPINNER_TEMPLATE,
            PLAIN_COUNTED_SPINNER_TEMPLATE,
            COLOR_COUNTED_SPINNER_TEMPLATE,
        ] {
            assert!(template.contains("{elapsed_precise}"));
            assert!(!template.contains("{percent"));
            assert!(!template.contains("{eta"));
        }
    }

    #[test]
    fn every_progress_template_is_accepted_by_indicatif() {
        for template in [
            PLAIN_BAR_TEMPLATE,
            COLOR_BAR_TEMPLATE,
            PLAIN_SPINNER_TEMPLATE,
            COLOR_SPINNER_TEMPLATE,
            PLAIN_COUNTED_SPINNER_TEMPLATE,
            COLOR_COUNTED_SPINNER_TEMPLATE,
        ] {
            ProgressStyle::with_template(template)
                .unwrap_or_else(|error| panic!("invalid progress template {template:?}: {error}"));
        }
    }
}
