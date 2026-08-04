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

use crate::theme::Theme;

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

pub(crate) fn init(path: Option<&Path>, html_theme: Option<Theme>) -> Result<()> {
    anyhow::ensure!(
        html_theme.is_none() || path.is_some(),
        "HTML output requires a destination path"
    );
    let mut state = lock_state();
    state.error = None;
    state.html = html_theme.is_some();
    state.html_closed = false;
    state.writer = match path {
        Some(path) => {
            let file =
                File::create(path).with_context(|| format!("creating output file {}", path.display()))?;
            let mut writer = BufWriter::with_capacity(1024 * 1024, file);
            if let Some(theme) = html_theme {
                writer
                    .write_all(html_header(theme).as_bytes())
                    .with_context(|| format!("writing HTML header to {}", path.display()))?;
            }
            Some(writer)
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
    let html = state.html;
    let Some(writer) = state.writer.as_mut() else {
        return false;
    };
    let result = if html {
        write_html_escaped(writer, bytes)
            .and_then(|()| suffix.map_or(Ok(()), |suffix| write_html_escaped(writer, suffix)))
    } else {
        writer
            .write_all(bytes)
            .and_then(|()| suffix.map_or(Ok(()), |suffix| writer.write_all(suffix)))
    };
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
    let html = state.html;
    if let Some(writer) = state.writer.as_mut() {
        let result = if html {
            let mut escaped = HtmlEscapingWriter { inner: writer };
            f(&mut escaped)?
        } else {
            f(writer)?
        };
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
                .write_all(
                    b"</pre></main><footer>bonsai-ninja static code intelligence</footer></body></html>\n",
                )
                .context("writing HTML report footer")?;
        }
        writer.flush().context("flushing output file")?;
    }
    if close_html {
        state.html_closed = true;
    }
    Ok(())
}

struct HtmlEscapingWriter<'a> {
    inner: &'a mut dyn Write,
}

impl Write for HtmlEscapingWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        write_html_escaped(self.inner, bytes)?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

fn write_html_escaped(writer: &mut dyn Write, bytes: &[u8]) -> std::io::Result<()> {
    let mut start = 0usize;
    for (index, byte) in bytes.iter().copied().enumerate() {
        let escaped: Option<&[u8]> = match byte {
            b'&' => Some(b"&amp;"),
            b'<' => Some(b"&lt;"),
            b'>' => Some(b"&gt;"),
            _ => None,
        };
        let Some(escaped) = escaped else {
            continue;
        };
        writer.write_all(&bytes[start..index])?;
        writer.write_all(escaped)?;
        start = index + 1;
    }
    writer.write_all(&bytes[start..])
}

fn html_header(theme: Theme) -> String {
    let (theme_name, background, panel, border, heading, text, muted, accent) = match theme {
        Theme::Moss => (
            "Moss", "#08110f", "#0d1a17", "#2a3a3c", "#78bcb4", "#a8deda", "#5c767a", "#6ec4d2",
        ),
        Theme::EarthyDark => (
            "Earthy Dark",
            "#15130f",
            "#211e18",
            "#5a5246",
            "#d9c38d",
            "#eadbb4",
            "#8b826e",
            "#d69a5b",
        ),
        Theme::Dracula => (
            "Dracula", "#1e1f29", "#282a36", "#44475a", "#bd93f9", "#f8f8f2", "#6272a4", "#ff79c6",
        ),
        Theme::RetroAmber => (
            "Retro Amber",
            "#100b00",
            "#1b1200",
            "#6e4a00",
            "#ffb000",
            "#ffd17a",
            "#946200",
            "#cc8800",
        ),
    };
    format!(
        "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>bonsai-ninja report</title><style>\n\
         :root{{--bg:{background};--panel:{panel};--border:{border};--heading:{heading};--text:{text};--muted:{muted};--accent:{accent}}}\n\
         *{{box-sizing:border-box}} body{{margin:0;background:var(--bg);color:var(--text);font-family:Inter,ui-sans-serif,system-ui,sans-serif}}\n\
         header,main,footer{{width:min(1180px,calc(100% - 32px));margin-inline:auto}}\n\
         header{{display:flex;align-items:center;gap:14px;padding:28px 0 18px;border-bottom:1px solid var(--border)}}\n\
         .mark{{display:grid;place-items:center;width:38px;height:38px;border:1px solid var(--accent);border-radius:10px;color:var(--accent);font:700 20px ui-monospace,monospace}}\n\
         h1{{margin:0;color:var(--heading);font-size:20px;letter-spacing:.02em}} .sub{{color:var(--muted);font-size:12px;margin-top:3px}}\n\
         .theme{{margin-left:auto;color:var(--muted);font:12px ui-monospace,monospace}}\n\
         main{{margin-top:22px;margin-bottom:22px;background:var(--panel);border:1px solid var(--border);border-radius:12px;overflow:auto;box-shadow:0 18px 50px #0005}}\n\
         pre{{margin:0;padding:22px;min-width:max-content;color:var(--text);font:13px/1.55 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;tab-size:4}}\n\
         footer{{padding:0 0 28px;color:var(--muted);font-size:12px}} @media(max-width:640px){{header,main,footer{{width:min(100% - 18px,1180px)}}pre{{padding:14px}}.theme{{display:none}}}}\n\
         </style></head><body><header><div class=\"mark\">盆</div><div><h1>bonsai-ninja</h1><div class=\"sub\">static code intelligence report</div></div><div class=\"theme\">{theme_name} theme</div></header><main><pre>"
    )
}

#[cfg(test)]
mod tests {
    use super::{html_header, write_html_escaped};
    use crate::theme::Theme;

    #[test]
    fn html_writer_escapes_source_and_renderer_markup() {
        let mut rendered = Vec::new();
        write_html_escaped(&mut rendered, br#"if a < b && value > 0 { "<tag>" }"#)
            .expect("escape HTML output");
        assert_eq!(
            String::from_utf8(rendered).expect("escaped output is utf8"),
            r#"if a &lt; b &amp;&amp; value &gt; 0 { "&lt;tag&gt;" }"#
        );
    }

    #[test]
    fn every_theme_builds_a_responsive_standalone_header() {
        for theme in [Theme::Moss, Theme::EarthyDark, Theme::Dracula, Theme::RetroAmber] {
            let header = html_header(theme);
            assert!(header.starts_with("<!doctype html>"));
            assert!(header.contains("<meta name=\"viewport\""));
            assert!(header.contains("@media(max-width:640px)"));
            assert!(header.ends_with("<main><pre>"));
        }
    }
}
