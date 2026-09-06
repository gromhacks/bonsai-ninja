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
use std::io::{BufWriter, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, OnceLock};

use crate::html::HtmlDocumentContext;

#[derive(Default)]
struct OutputState {
    writer: Option<BufWriter<File>>,
    pending: Option<(tempfile::TempPath, PathBuf)>,
    html: bool,
    html_closed: bool,
    error: Option<String>,
    terminal_progress: Option<crate::progress::OutputProgressGuard<'static>>,
}

static OUTPUT: OnceLock<Mutex<OutputState>> = OnceLock::new();

fn state() -> &'static Mutex<OutputState> {
    OUTPUT.get_or_init(|| Mutex::new(OutputState::default()))
}

fn lock_state() -> MutexGuard<'static, OutputState> {
    state().lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Discard an unpublished report on errors or unwinding, including errors
/// before command dispatch. Successful `finish` has already consumed it.
pub(crate) struct OutputGuard;

impl Drop for OutputGuard {
    fn drop(&mut self) {
        let discarded = std::mem::take(&mut *lock_state());
        drop(discarded);
    }
}

pub(crate) fn init(
    path: Option<&Path>,
    html: Option<&HtmlDocumentContext>,
    atomic: bool,
) -> Result<OutputGuard> {
    anyhow::ensure!(
        html.is_none() || path.is_some(),
        "HTML output requires a destination path"
    );
    let mut pending = None;
    let writer = match path {
        Some(path) => {
            let metadata = match std::fs::symlink_metadata(path) {
                Ok(metadata) => Some(metadata),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
                Err(error) => {
                    return Err(error).with_context(|| format!("checking output file {}", path.display()))
                }
            };
            // Follow existing symlinks just as an ordinary file sink does;
            // replacing a symlink itself would change a different target.
            let destination = if metadata.as_ref().is_some_and(|metadata| metadata.is_symlink()) {
                path.canonicalize()
                    .with_context(|| format!("resolving output symlink {}", path.display()))?
            } else {
                path.to_path_buf()
            };
            let target_metadata = destination.metadata().ok();
            let file = if atomic && target_metadata.as_ref().is_none_or(std::fs::Metadata::is_file) {
                let parent = destination
                    .parent()
                    .filter(|parent| !parent.as_os_str().is_empty())
                    .unwrap_or_else(|| Path::new("."));
                let parent = parent
                    .canonicalize()
                    .with_context(|| format!("resolving output directory {}", parent.display()))?;
                let temporary = tempfile::Builder::new()
                    .prefix(".bonsai-output-")
                    .tempfile_in(&parent)
                    .with_context(|| format!("preparing output file {}", path.display()))?;
                if let Some(metadata) = target_metadata {
                    anyhow::ensure!(
                        !metadata.permissions().readonly(),
                        "output file {} is read-only",
                        path.display()
                    );
                    temporary.as_file().set_permissions(metadata.permissions())?;
                }
                let (file, temporary_path) = temporary.into_parts();
                pending = Some((temporary_path, destination));
                file
            } else {
                // Explicit watch streams and device sinks remain streaming.
                File::create(&destination)
                    .with_context(|| format!("creating output file {}", path.display()))?
            };
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
    *lock_state() = OutputState {
        writer,
        pending,
        html: html.is_some(),
        ..OutputState::default()
    };
    Ok(OutputGuard)
}

/// True when `--html-output` is active and structured documents must be
/// rendered as HTML fragments instead of pretty JSON.
pub(crate) fn html_enabled() -> bool {
    lock_state().html
}

/// Hide only this command's exact temporary report from filesystem navigation.
/// A prefix filter would incorrectly hide user-owned files with similar names.
pub(crate) fn is_pending_output_path(path: &Path) -> bool {
    lock_state().pending.as_ref().is_some_and(|(temporary, _)| {
        let temporary: &Path = temporary.as_ref();
        temporary == path
    })
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

/// Once a terminal report starts, later compiler phases must not redraw
/// progress between its lines. Keep this guard until command teardown, not
/// merely until one write finishes. Device-file terminal sinks count too.
pub(crate) fn begin_report() {
    let mut state = lock_state();
    if state.terminal_progress.is_none()
        && state.writer.as_ref().map_or_else(
            || std::io::stdout().is_terminal(),
            |writer| writer.get_ref().is_terminal(),
        )
    {
        state.terminal_progress = Some(crate::progress::OutputProgressGuard::new());
    }
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
    begin_report();
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
    // Close the writer before rename, including on Windows. A failed command
    // never reaches this publication point and leaves an existing report intact.
    drop(state.writer.take());
    if let Some((temporary, destination)) = state.pending.take() {
        temporary
            .persist(&destination)
            .map_err(|error| error.error)
            .with_context(|| format!("publishing output file {}", destination.display()))?;
    }
    Ok(())
}
