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
//! - `idg-query` — persisted IDG accelerator load, warm-up, and query
//!   runtime timings.
//! - `recv-state` — receiver-state propagation matches and seeded
//!   downstream consumers.
//! - `find-group` — finding combination + grouping decisions
//!   (which finding becomes group primary vs additional source).
//! - `taint-graph` — `EntryTaintGraph` cross-call edge ordering.
//! - `workspace-open`, `compiler-cache`, `page-cache`, `security-phase` —
//!   ingest, compiler-object, rendered-page, and security phase timings.
//!
//! Tests should never depend on debug output — the env variable is
//! a developer convenience, not a public API.

use std::sync::{OnceLock, RwLock};

/// Cached category set parsed from `BONSAI_DEBUG`. The
/// [`is_enabled`] check resolves through this cell so the environment
/// is read at most once per process — matters for hot per-call sites
/// like the IDG transfer pass.
static ENABLED: OnceLock<EnabledSet> = OnceLock::new();

// Keep the ordinary compiler hot path lock-free. Only callers that explicitly
// reset test configuration install this mutable override.
static TEST_OVERRIDE: OnceLock<RwLock<EnabledSet>> = OnceLock::new();

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
        Self::from_raw(&raw)
    }

    fn from_raw(raw: &str) -> Self {
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
    if let Some(override_set) = TEST_OVERRIDE.get() {
        return override_set
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .contains(category);
    }
    ENABLED.get_or_init(EnabledSet::from_env).contains(category)
}

/// Re-read `BONSAI_DEBUG` and replace the process-wide test configuration.
/// Tests that change the environment must isolate those changes from other
/// readers (for example in a subprocess); production never needs this helper.
pub fn reset_for_tests() {
    let set = TEST_OVERRIDE.get_or_init(|| RwLock::new(EnabledSet::from_raw("")));
    *set.write().unwrap_or_else(std::sync::PoisonError::into_inner) = EnabledSet::from_env();
}

/// Emit a categorised debug line to stderr when `category` is
/// enabled in the runtime filter. Cheap when disabled — only an
/// `is_enabled` lookup runs; argument expressions are unevaluated
/// thanks to the `if`-guard pattern.
///
/// Usage:
/// ```no_run
/// use bonsai_diagnostics::debug_log;
/// # let name = "entry";
/// # let size = 1usize;
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
