//! Optional command-output file sink.
//!
//! Renderers keep writing through the existing CLI print macros (or,
//! for `export`, through a `Write` sink). This module owns the small
//! process-wide switch that redirects the selected command payload to
//! `--output-path` / `--html-output` while progress bars, diagnostics,
//! and the footer stay on stderr.
//!
//! Under `--html-output` the command runs in its JSON mode and every
//! structured document it emits passes through [`emit_json_document`],
//! which renders the canonical object as an HTML fragment. The sink only
//! adds the document head and tail; it never escapes or rewrites what the
//! renderers produce.

use anyhow::{Context, Result};
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;
use std::sync::{Mutex, MutexGuard, OnceLock};

use crate::html::HtmlDocumentContext;

#[derive(Default)]
struct OutputState {
    writer: Option<BufWriter<File>>,
    html: bool,
    html_closed: bool,
    error: Option<String>,
}

static OUTPUT: OnceLock<Mutex<OutputState>> = OnceLock::new();

fn state() -> &'static Mutex<OutputState> {
    OUTPUT.get_or_init(|| Mutex::new(OutputState::default()))
}

fn lock_state() -> MutexGuard<'static, OutputState> {
    state().lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

pub(crate) fn init(path: Option<&Path>, html: Option<&HtmlDocumentContext>) -> Result<()> {
    anyhow::ensure!(
        html.is_none() || path.is_some(),
        "HTML output requires a destination path"
    );
    let mut state = lock_state();
    state.error = None;
    state.html = html.is_some();
    state.html_closed = false;
    state.writer = match path {
        Some(path) => {
            let file =
                File::create(path).with_context(|| format!("creating output file {}", path.display()))?;
            let mut writer = BufWriter::with_capacity(1024 * 1024, file);
            if let Some(context) = html {
                writer
                    .write_all(crate::html::document_head(context).as_bytes())
                    .with_context(|| format!("writing HTML document head to {}", path.display()))?;
            }
            Some(writer)
        }
        None => None,
    };
    Ok(())
}

/// True when `--html-output` is active and structured documents must be
/// rendered as HTML fragments instead of pretty JSON.
pub(crate) fn html_enabled() -> bool {
    lock_state().html
}

/// Print one canonical command document. Pretty JSON normally; under
/// `--html-output` the same object is rendered as an HTML fragment so the
/// report is derived from the command result rather than from terminal text.
pub(crate) fn emit_json_document<T: serde::Serialize>(value: &T) -> Result<()> {
    if html_enabled() {
        let value = serde_json::to_value(value)?;
        crate::cli_println!("{}", crate::html::render_fragment(&value));
    } else {
        crate::cli_println!("{}", serde_json::to_string_pretty(value)?);
    }
    Ok(())
}

pub(crate) fn write_line(s: &str) -> bool {
    write_parts(s.as_bytes(), Some(b"\n"), s, true)
}

pub(crate) fn write_str(s: &str) -> bool {
    write_parts(s.as_bytes(), None, s, false)
}

pub(crate) fn write_raw_counted(s: &str) -> bool {
    write_parts(s.as_bytes(), None, s, false)
}

fn write_parts(bytes: &[u8], suffix: Option<&[u8]>, visible: &str, trailing_newline: bool) -> bool {
    let mut state = lock_state();
    let Some(writer) = state.writer.as_mut() else {
        return false;
    };
    let result = writer
        .write_all(bytes)
        .and_then(|()| suffix.map_or(Ok(()), |suffix| writer.write_all(suffix)));
    match result {
        Ok(()) => crate::out_count::add_counting(visible, trailing_newline),
        Err(error) => state.error = Some(error.to_string()),
    }
    true
}

pub(crate) fn with_writer<T, F>(f: F) -> Result<T>
where
    F: FnOnce(&mut dyn Write) -> Result<T>,
{
    let mut state = lock_state();
    if let Some(error) = state.error.take() {
        anyhow::bail!("writing output file failed: {error}");
    }
    if let Some(writer) = state.writer.as_mut() {
        let result = f(writer)?;
        writer.flush().context("flushing output file")?;
        Ok(result)
    } else {
        drop(state);
        let stdout = std::io::stdout();
        let mut writer = BufWriter::with_capacity(1024 * 1024, stdout.lock());
        let result = f(&mut writer)?;
        writer.flush().context("flushing stdout")?;
        Ok(result)
    }
}

pub(crate) fn finish() -> Result<()> {
    let mut state = lock_state();
    if let Some(error) = state.error.take() {
        anyhow::bail!("writing output file failed: {error}");
    }
    let close_html = state.html && !state.html_closed;
    if let Some(writer) = state.writer.as_mut() {
        if close_html {
            writer
                .write_all(crate::html::document_tail().as_bytes())
                .context("writing HTML document tail")?;
        }
        writer.flush().context("flushing output file")?;
    }
    if close_html {
        state.html_closed = true;
    }
    Ok(())
}
