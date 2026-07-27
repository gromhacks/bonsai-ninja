//! Optional command-output file sink.
//!
//! Renderers keep writing through the existing CLI print macros (or,
//! for `export`, through a `Write` sink). This module owns the small
//! process-wide switch that redirects the selected command payload to
//! `--output-path` while progress bars, diagnostics, and the footer stay
//! on stderr.

use anyhow::{Context, Result};
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;
use std::sync::{Mutex, MutexGuard, OnceLock};

#[derive(Default)]
struct OutputState {
    writer: Option<BufWriter<File>>,
    error: Option<String>,
}

static OUTPUT: OnceLock<Mutex<OutputState>> = OnceLock::new();

fn state() -> &'static Mutex<OutputState> {
    OUTPUT.get_or_init(|| Mutex::new(OutputState::default()))
}

fn lock_state() -> MutexGuard<'static, OutputState> {
    state().lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

pub(crate) fn init(path: Option<&Path>) -> Result<()> {
    let mut state = lock_state();
    state.error = None;
    state.writer = match path {
        Some(path) => {
            let file =
                File::create(path).with_context(|| format!("creating output file {}", path.display()))?;
            Some(BufWriter::with_capacity(1024 * 1024, file))
        }
        None => None,
    };
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
    if let Some(writer) = state.writer.as_mut() {
        writer.flush().context("flushing output file")?;
    }
    Ok(())
}
