use crate::progress;
use indicatif::ProgressBar;
use std::time::Instant;

/// Renders one progress bar per `AnalysisProgress` phase emitted by the
/// security analysis pipeline. Each `PhaseStarted` opens a fresh bar
/// with the announced total, `PhaseTicked` increments it, and
/// `PhaseFinished` clears it. `Drop` is the safety net for early
/// returns / errors that bypass the explicit `PhaseFinished`.
pub(super) struct SecurityAnalysisProgress {
    bar: Option<ProgressBar>,
    phase_label: Option<&'static str>,
    phase_started: Option<Instant>,
    phase_ticks: u64,
}

pub(super) struct ScopedProgress {
    bar: Option<ProgressBar>,
    label: String,
    started: Instant,
    finished: bool,
}

impl ScopedProgress {
    pub(super) fn new(label: &str) -> Self {
        Self {
            bar: Some(progress::spinner(label)),
            label: label.to_string(),
            started: Instant::now(),
            finished: false,
        }
    }

    pub(super) fn finish(mut self) {
        self.finished = true;
        if let Some(bar) = self.bar.take() {
            bar.finish_and_clear();
        }
        self.log_timing();
    }

    fn log_timing(&self) {
        if !progress::is_explicitly_disabled() && progress::debug_category_enabled("security-phase") {
            eprintln!(
                "[security-phase] {}: {:.3}s",
                self.label,
                self.started.elapsed().as_secs_f64()
            );
        }
    }
}

impl Drop for ScopedProgress {
    fn drop(&mut self) {
        if let Some(bar) = self.bar.take() {
            bar.finish_and_clear();
        }
        if !self.finished {
            self.log_timing();
        }
    }
}

impl SecurityAnalysisProgress {
    pub(super) fn new() -> Self {
        Self {
            bar: None,
            phase_label: None,
            phase_started: None,
            phase_ticks: 0,
        }
    }

    pub(super) fn handle(&mut self, event: bonsai_sdk::AnalysisProgress) {
        match event {
            bonsai_sdk::AnalysisProgress::PhaseStarted { label, total } => {
                self.finish_active_phase();
                self.bar = Some(if total == 0 {
                    progress::spinner(label)
                } else {
                    progress::progress_bar(label, total)
                });
                self.phase_label = Some(label);
                self.phase_started = Some(Instant::now());
                self.phase_ticks = 0;
            }
            bonsai_sdk::AnalysisProgress::PhaseTicked => {
                self.phase_ticks = self.phase_ticks.saturating_add(1);
                if let Some(bar) = &self.bar {
                    if self.phase_ticks == 1 && bar.length().is_none() {
                        progress::show_spinner_count(bar);
                    }
                    bar.inc(1);
                }
            }
            bonsai_sdk::AnalysisProgress::PhaseFinished => {
                self.finish_active_phase();
            }
            bonsai_sdk::AnalysisProgress::Note { label, detail } => {
                if !progress::is_explicitly_disabled()
                    && progress::debug_category_enabled("security-progress")
                {
                    let rendered = render_progress_note(label, &detail);
                    if let Some(bar) = &self.bar {
                        bar.suspend(|| eprintln!("  [security-progress] {rendered}"));
                    } else {
                        eprintln!("  [security-progress] {rendered}");
                    }
                }
            }
        }
    }

    fn finish_active_phase(&mut self) {
        if let Some(bar) = self.bar.take() {
            bar.finish_and_clear();
        }
        self.log_phase_timing();
        self.phase_label = None;
        self.phase_started = None;
        self.phase_ticks = 0;
    }

    fn log_phase_timing(&self) {
        if progress::is_explicitly_disabled() || !progress::debug_category_enabled("security-phase") {
            return;
        }
        let (Some(label), Some(started)) = (self.phase_label, self.phase_started) else {
            return;
        };
        eprintln!(
            "[security-phase] {label}: {:.3}s · {}",
            started.elapsed().as_secs_f64(),
            phase_step_summary(self.phase_ticks)
        );
    }
}

impl Drop for SecurityAnalysisProgress {
    fn drop(&mut self) {
        self.finish_active_phase();
    }
}

fn render_progress_note(label: &str, detail: &str) -> String {
    match label {
        "scope" => render_scope_note(detail),
        "taint-cache" => render_taint_cache_note(detail),
        _ => format!("{label}: {}", humanize_detail(detail)),
    }
}

fn render_scope_note(detail: &str) -> String {
    let Some((subject, rest)) = detail.split_once(' ') else {
        return format!("analysis scope: {}", humanize_detail(detail));
    };
    let subject = humanize_subject(subject);
    let mut parts = Vec::new();
    let fields = key_value_fields(rest);
    for (key, value) in fields {
        match key {
            "files" => parts.push(counted(value, "file", "files")),
            "source_rules" => parts.push(counted(value, "source rule", "source rules")),
            "sink_rules" => parts.push(counted(value, "sink rule", "sink rules")),
            "sanitizer_rules" => parts.push(counted(value, "sanitizer rule", "sanitizer rules")),
            "include_inferred_sources" => parts.push(format!("inferred sources {}", on_off(value))),
            "exclude_tests" => parts.push(if value == "true" {
                "tests excluded".to_string()
            } else {
                "tests included".to_string()
            }),
            "file_filters" => parts.push(counted(value, "file filter", "file filters")),
            "exclude_filters" => parts.push(counted(value, "exclude filter", "exclude filters")),
            "source_matches" => parts.push(counted(value, "source match", "source matches")),
            "endpoint_files" => parts.push(counted(value, "endpoint file", "endpoint files")),
            "source_languages" => parts.push(counted(value, "source language", "source languages")),
            "max_precision" => parts.push(format!("static evidence {}", humanize_precision_value(value))),
            "static_evidence" => parts.push(format!("static evidence {}", humanize_precision_value(value))),
            "sink_matches" => parts.push(counted(value, "sink match", "sink matches")),
            "sanitizer_matches" => parts.push(counted(value, "sanitizer match", "sanitizer matches")),
            "pattern_sinks" => parts.push(counted(value, "pattern sink", "pattern sinks")),
            "source_groups" => parts.push(counted(value, "source group", "source groups")),
            "scheduled_groups" => parts.push(counted(value, "scheduled group", "scheduled groups")),
            "reachable_funcs" => parts.push(counted(value, "reachable function", "reachable functions")),
            "source_sink_prefilter" => parts.push(format!("prefilter {}", on_off(value))),
            "source_jobs" => parts.push(counted(value, "source job", "source jobs")),
            "source_graph_groups" => parts.push(counted(value, "source graph group", "source graph groups")),
            "functions" => parts.push(counted(value, "function", "functions")),
            _ => parts.push(format!("{} {}", key.replace('_', " "), value)),
        }
    }
    if parts.is_empty() {
        format!("{subject} scope: {}", humanize_detail(rest))
    } else {
        format!("{subject} scope: {}", parts.join(" · "))
    }
}

fn render_taint_cache_note(detail: &str) -> String {
    if let Some(entries) = detail.strip_prefix("finish write-through entries=") {
        return format!(
            "taint graph cache: write-through saved {}",
            counted(entries, "entry", "entries")
        );
    }
    if detail == "finish write-through failed" {
        return "taint graph cache: write-through failed".to_string();
    }

    let mut parts = Vec::new();
    for raw in detail.split(';').map(str::trim).filter(|part| !part.is_empty()) {
        if let Some((key, value)) = raw.split_once('=') {
            match key {
                "sidecar" => parts.push(format!("sidecar {}", compact_sidecar(value))),
                "disk_entries" => parts.push(counted(value, "disk entry", "disk entries")),
                "resident_before" => parts.push(format!("resident before {value}")),
                "total_before" => parts.push(format!("total before {value}")),
                "temp_removed" => {
                    parts.push(format!("{} removed", counted(value, "temp file", "temp files")));
                }
                _ => parts.push(format!("{} {}", key.replace('_', " "), value)),
            }
        } else {
            parts.push(raw.to_string());
        }
    }
    if parts.is_empty() {
        "taint graph cache: no details".to_string()
    } else {
        format!("taint graph cache: {}", parts.join(" · "))
    }
}

fn humanize_detail(detail: &str) -> String {
    detail
        .split_whitespace()
        .map(|part| {
            if let Some((key, value)) = part.split_once('=') {
                format!("{} {}", key.replace('_', " "), value)
            } else {
                part.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join(" · ")
}

fn key_value_fields(input: &str) -> Vec<(&str, &str)> {
    input
        .split_whitespace()
        .filter_map(|part| part.split_once('='))
        .collect()
}

fn on_off(value: &str) -> &'static str {
    if value == "true" {
        "on"
    } else {
        "off"
    }
}

fn counted(value: &str, singular: &str, plural: &str) -> String {
    format!("{value} {}", if value == "1" { singular } else { plural })
}

fn humanize_subject(subject: &str) -> String {
    subject.replace('-', " ")
}

fn humanize_precision_value(value: &str) -> String {
    value.replace('+', " + ").replace('_', "-")
}

fn phase_step_summary(steps: u64) -> String {
    let count = steps.to_string();
    counted(&count, "step", "steps")
}

fn compact_sidecar(path: &str) -> String {
    let Some(file_name) = path.rsplit(['/', '\\']).next().filter(|name| !name.is_empty()) else {
        return path.to_string();
    };
    format!("$CACHE_DIR/{file_name}")
}

#[cfg(test)]
mod tests {
    use super::render_progress_note;

    #[test]
    fn scope_notes_render_as_human_progress_lines() {
        let rendered = render_progress_note(
            "scope",
            "taint-analysis files=8 source_rules=95 sink_rules=386 sanitizer_rules=99 include_inferred_sources=false exclude_tests=false file_filters=0 exclude_filters=0",
        );

        assert_eq!(
            rendered,
            "taint analysis scope: 8 files · 95 source rules · 386 sink rules · 99 sanitizer rules · inferred sources off · tests included · 0 file filters · 0 exclude filters"
        );
        assert!(!rendered.contains("files=8"));
    }

    #[test]
    fn scope_notes_render_static_evidence_as_accuracy_contract() {
        let rendered = render_progress_note(
            "scope",
            "taint-analysis source_matches=3 endpoint_files=8 source_languages=1 static_evidence=exact+narrowed",
        );

        assert_eq!(
            rendered,
            "taint analysis scope: 3 source matches · 8 endpoint files · 1 source language · static evidence exact + narrowed"
        );
        assert!(!rendered.contains("max_precision"));
    }

    #[test]
    fn taint_cache_notes_hide_absolute_paths_and_raw_keys() {
        let rendered = render_progress_note(
            "taint-cache",
            "disk hit; resident config refreshed; sidecar=/tmp/work/.bonsai/taint_graph.v9.taint-analysis.0123456789abcdef.factstore; disk_entries=6; resident_before=0/0; total_before=0; temp_removed=0; write-through on",
        );

        assert_eq!(
            rendered,
            "taint graph cache: disk hit · resident config refreshed · sidecar $CACHE_DIR/taint_graph.v9.taint-analysis.0123456789abcdef.factstore · 6 disk entries · resident before 0/0 · total before 0 · 0 temp files removed · write-through on"
        );
        assert!(!rendered.contains("/tmp/work"));
        assert!(!rendered.contains("disk_entries="));
    }

    #[test]
    fn taint_cache_notes_hide_windows_absolute_sidecar_paths() {
        let rendered = render_progress_note(
            "taint-cache",
            r"disk hit; sidecar=C:\work\project\.bonsai\taint_graph.v9.taint-analysis.0123456789abcdef.factstore; disk_entries=6",
        );

        assert_eq!(
            rendered,
            "taint graph cache: disk hit · sidecar $CACHE_DIR/taint_graph.v9.taint-analysis.0123456789abcdef.factstore · 6 disk entries"
        );
        assert!(!rendered.contains(r"C:\work"));
        assert!(!rendered.contains("disk_entries="));
    }

    #[test]
    fn taint_cache_finish_note_is_short() {
        assert_eq!(
            render_progress_note("taint-cache", "finish write-through entries=6"),
            "taint graph cache: write-through saved 6 entries"
        );
    }

    #[test]
    fn phase_progress_counts_use_user_facing_steps() {
        assert_eq!(super::phase_step_summary(0), "0 steps");
        assert_eq!(super::phase_step_summary(1), "1 step");
        assert_eq!(super::phase_step_summary(8), "8 steps");
    }
}
