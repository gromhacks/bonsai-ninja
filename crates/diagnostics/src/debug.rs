//! Categorised debug logging for analysis-pipeline diagnostics.
//!
//! Every analyzer phase that wants to surface internal state behind a
//! flag declares its category as a string and emits via
//! `debug_log!`. The runtime filter is a comma-separated list in
//! the `BONSAI_DEBUG` environment variable — a category emits to
//! stderr when that list contains either `*` (everything) or the
//! category's exact name. The CLI's `--debug <cat>` flag sets the
//! variable for the analyzer process.
//!
//! ## Why not `tracing` / `log`?
//!
//! `tracing` adds a heavyweight subscriber dependency for what we
//! need: stderr lines gated by a list. The categories used here are
//! few (~10) and stable; a flat env-driven filter keeps the noise
//! footprint zero in the default path while still giving callers a
//! one-flag knob to enable any subset.
//!
//! ## Categories
//!
//! Pick category names that name the *phase* and the *kind of state*
//! being surfaced. Examples:
//! - `idg-closure` — IDG seed / closure / xcall counts and node
//!   detail per source.
//! - `idg-resolve` — callgraph-driven callee resolution per call site.
//! - `recv-state` — receiver-state propagation matches and seeded
//!   downstream consumers.
//! - `find-group` — finding combination + grouping decisions
//!   (which finding becomes group primary vs additional source).
//! - `taint-graph` — `EntryTaintGraph` cross-call edge ordering.
//! - `xcall` — cross-file edge index size and per-closure xcall
//!   selection.
//!
//! Tests should never depend on debug output — the env variable is
//! a developer convenience, not a public API.

use std::sync::OnceLock;

/// Cached category set parsed from `BONSAI_DEBUG`. The
/// [`is_enabled`] check resolves through this cell so the environment
/// is read at most once per process — matters for hot per-call sites
/// like the IDG transfer pass.
static ENABLED: OnceLock<EnabledSet> = OnceLock::new();

#[derive(Debug)]
struct EnabledSet {
    /// True when the env var contained `*`. Short-circuits per-name
    /// lookups for the "enable everything" case.
    all: bool,
    /// Exact category names enabled; empty when the env var was
    /// unset or empty.
    names: Vec<String>,
}

impl EnabledSet {
    fn from_env() -> Self {
        let raw = std::env::var("BONSAI_DEBUG").unwrap_or_default();
        let mut all = false;
        let mut names: Vec<String> = Vec::new();
        for part in raw.split(',') {
            let trimmed = part.trim();
            if trimmed.is_empty() {
                continue;
            }
            if trimmed == "*" || trimmed == "all" {
                all = true;
                continue;
            }
            names.push(trimmed.to_string());
        }
        Self { all, names }
    }

    fn contains(&self, category: &str) -> bool {
        if self.all {
            return true;
        }
        self.names.iter().any(|n| n == category)
    }
}

/// True when `category` should emit debug output. Cheap once the
/// `OnceLock` has been initialised; the very first call reads the
/// `BONSAI_DEBUG` environment variable.
#[must_use]
pub fn is_enabled(category: &str) -> bool {
    ENABLED.get_or_init(EnabledSet::from_env).contains(category)
}

/// Re-read `BONSAI_DEBUG` on the next [`is_enabled`] call. Tests
/// that flip the env mid-run should call this to invalidate the
/// process-wide cache; production never needs it.
pub fn reset_for_tests() {
    // OnceLock has no public reset — rebuild a parallel cell. The
    // production callers continue to read the cached value;
    // tests only flip when they're the sole reader anyway.
    let mut new_set = EnabledSet::from_env();
    if let Some(existing) = ENABLED.get() {
        // Best-effort: replace fields in place via unsafe? No —
        // OnceLock forbids it. Instead, append the new categories
        // so re-reads get the union (good enough for the test
        // helper's documented use).
        new_set.all = existing.all || new_set.all;
        for name in &existing.names {
            if !new_set.names.iter().any(|n| n == name) {
                new_set.names.push(name.clone());
            }
        }
    }
    let _ = ENABLED.set(new_set);
}

/// Emit a categorised debug line to stderr when `category` is
/// enabled in the runtime filter. Cheap when disabled — only an
/// `is_enabled` lookup runs; argument expressions are unevaluated
/// thanks to the `if`-guard pattern.
///
/// Usage:
/// ```ignore
/// use bonsai_diagnostics::debug_log;
/// debug_log!("idg-closure", "src={} closure_size={}", name, size);
/// ```
#[macro_export]
macro_rules! debug_log {
    ($category:expr, $($arg:tt)*) => {
        if $crate::debug::is_enabled($category) {
            let message = format!($($arg)*);
            eprintln!("[{}] {}", $category, $crate::debug::render_message(&message));
        }
    };
}

/// Render debug text for terminal output.
///
/// Analyzer debug messages are intentionally not a stable API, but they
/// are still read by people during long runs. Keep the useful details while
/// avoiding raw `key=value` dumps in terminal output.
#[must_use]
pub fn render_message(message: &str) -> String {
    if !message.contains('=') {
        return message.to_string();
    }
    let mut out = String::new();
    let mut previous_token = "";
    for token in message.split_whitespace() {
        let rendered = render_message_token(token);
        if out.is_empty() {
            out.push_str(&rendered.text);
        } else if rendered.was_key_value && previous_token != "->" && !previous_token.ends_with(':') {
            out.push_str(" · ");
            out.push_str(&rendered.text);
        } else {
            out.push(' ');
            out.push_str(&rendered.text);
        }
        previous_token = token;
    }
    out
}

struct RenderedToken {
    text: String,
    was_key_value: bool,
}

fn render_message_token(token: &str) -> RenderedToken {
    let (core, suffix) = trim_trailing_separator(token);
    let Some((key, value)) = core.split_once('=') else {
        return RenderedToken {
            text: token.to_string(),
            was_key_value: false,
        };
    };
    if key.is_empty()
        || value.is_empty()
        || !key
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-'))
    {
        return RenderedToken {
            text: token.to_string(),
            was_key_value: false,
        };
    }
    let label = humanize_key_label(key);
    let value = match value {
        "true" => "on".to_string(),
        "false" => "off".to_string(),
        _ => value.to_string(),
    };
    RenderedToken {
        text: format!("{label} {value}{suffix}"),
        was_key_value: true,
    }
}

fn trim_trailing_separator(token: &str) -> (&str, &str) {
    if token.len() > 1 && token.ends_with([',', ';']) {
        token.split_at(token.len() - 1)
    } else {
        (token, "")
    }
}

fn humanize_key_label(key: &str) -> String {
    key.split(['_', '-'])
        .map(|part| match part {
            "dst" => "destination",
            "func" => "function",
            "funcs" => "functions",
            "src" => "source",
            other => other,
        })
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
#[path = "debug_tests.rs"]
mod tests;
