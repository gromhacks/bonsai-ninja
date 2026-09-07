//! `--html-output` renderer.
//!
//! The HTML report is generated from the command's canonical result — the
//! same JSON document `--format json` prints — never from the terminal text
//! view. Every command runs in its JSON mode under `--html-output`; each
//! structured document it emits is turned into an HTML fragment by
//! [`render_fragment`], and [`document_head`] / [`document_tail`] wrap the
//! fragments once per process. Because the fragment is derived from the
//! canonical object, the report contains exactly the facts JSON contains:
//! same selected objects, same filters, same page, same completeness
//! metadata, and no additional analysis.
//!
//! The renderer is deliberately generic over JSON shapes rather than
//! per-command: completeness fields become a status strip, scalar fields
//! become a fact list, arrays of flat records become tables, arrays of
//! nested records become cards, and multi-line or code-like strings become
//! `<pre>` blocks. The output contains no scripts and no external assets.

use serde_json::Value;
use std::fmt::Write as _;

/// Document identity shown in the report header.
pub(crate) struct HtmlDocumentContext {
    /// Short command path, e.g. `defs` or `security taint-analysis`.
    pub(crate) title: String,
    /// Complete command line minus the `--html-output` sink itself.
    pub(crate) command_line: String,
}

impl HtmlDocumentContext {
    /// Derive the title and command line from the current process argv.
    pub(crate) fn from_argv() -> Self {
        let args: Vec<String> = std::env::args().skip(1).collect();
        Self::from_args(&args)
    }

    pub(crate) fn from_args(args: &[String]) -> Self {
        let mut shown = Vec::with_capacity(args.len());
        let mut iter = args.iter().peekable();
        while let Some(arg) = iter.next() {
            if arg == "--html-output" {
                let _ = iter.next();
                continue;
            }
            if arg.starts_with("--html-output=") {
                continue;
            }
            shown.push(arg.clone());
        }
        let title = command_title(&shown);
        // The report is meant to be shared. Keep the command line
        // reproducible in shape but never embed a private absolute local
        // path: an absolute filesystem argument is shown by its last
        // component, relative arguments stay as typed.
        let command_line = std::iter::once("bonsai-ninja".to_string())
            .chain(shown.iter().map(|arg| shell_quote(&portable_argument(arg))))
            .collect::<Vec<_>>()
            .join(" ");
        Self { title, command_line }
    }
}

/// `security taint-analysis` for grouped commands, `defs` otherwise: the
/// subcommand chain clap would dispatch to, found by walking the real
/// command tree so global value flags (`--theme moss`) and positionals
/// (`security <WORKSPACE> pack`) are never mistaken for command names.
fn command_title(args: &[String]) -> String {
    use clap::CommandFactory as _;
    let mut command = crate::args::Cli::command();
    command.build();
    let mut chain: Vec<String> = Vec::new();
    let mut iter = args.iter().peekable();
    while let Some(arg) = iter.next() {
        if arg == "--" {
            break;
        }
        if let Some(flag) = arg.strip_prefix("--") {
            if flag.contains('=') {
                continue;
            }
            if flag_takes_value(&command, |a| a.get_long() == Some(flag)) {
                let _ = iter.next();
            }
            continue;
        }
        if let Some(short) = arg.strip_prefix('-').filter(|s| s.len() == 1) {
            let short = short.chars().next().unwrap_or_default();
            if flag_takes_value(&command, |a| a.get_short() == Some(short)) {
                let _ = iter.next();
            }
            continue;
        }
        if arg.starts_with('-') {
            continue;
        }
        if let Some(next) = command.find_subcommand(arg.as_str()) {
            chain.push(next.get_name().to_string());
            command = next.clone();
        }
    }
    if chain.is_empty() {
        "bonsai-ninja".to_string()
    } else {
        chain.join(" ")
    }
}

fn flag_takes_value(command: &clap::Command, matches: impl Fn(&clap::Arg) -> bool) -> bool {
    command
        .get_arguments()
        .find(|arg| matches(arg))
        .is_some_and(|arg| arg.get_action().takes_values())
}

fn portable_argument(arg: &str) -> String {
    let (flag, value) = match arg.split_once('=') {
        Some((flag, value)) if flag.starts_with("--") => (Some(flag), value),
        _ => (None, arg),
    };
    if !is_absolute_path_like(value) {
        return arg.to_string();
    }
    let shortened = value
        .trim_end_matches(['/', '\\'])
        .rsplit(['/', '\\'])
        .next()
        .filter(|name| !name.is_empty())
        .map_or_else(|| value.to_string(), |name| format!("<…>/{name}"));
    match flag {
        Some(flag) => format!("{flag}={shortened}"),
        None => shortened,
    }
}

fn is_absolute_path_like(value: &str) -> bool {
    let path = std::path::Path::new(value);
    path.is_absolute()
        || value.starts_with('/')
        || value.starts_with('\\')
        || value.as_bytes().get(1) == Some(&b':')
            && value
                .as_bytes()
                .get(2)
                .is_some_and(|byte| *byte == b'/' || *byte == b'\\')
}

fn shell_quote(arg: &str) -> String {
    if arg.is_empty() {
        return "''".to_string();
    }
    if arg
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'/' | b':' | b'=' | b','))
    {
        arg.to_string()
    } else {
        format!("'{}'", arg.replace('\'', "'\\''"))
    }
}

pub(crate) fn document_head(ctx: &HtmlDocumentContext) -> String {
    format!(
        "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">\
<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
<title>bonsai-ninja {title}</title>\n<style>{css}</style></head>\n<body>\n\
<header class=\"report-header\"><h1>bonsai-ninja <span class=\"cmd-name\">{title}</span></h1>\
<code class=\"cmd-line\">{command_line}</code></header>\n<main>\n",
        title = escape(&ctx.title),
        command_line = escape(&ctx.command_line),
        css = STYLESHEET,
    )
}

pub(crate) fn document_tail() -> &'static str {
    "</main>\n</body></html>\n"
}

/// Render one canonical command document as an HTML fragment.
pub(crate) fn render_fragment(value: &Value) -> String {
    let mut out = String::with_capacity(4096);
    out.push_str("<article class=\"result\">\n");
    match value {
        Value::Object(fields) => render_document_object(&mut out, fields),
        Value::Array(items) => {
            render_section(&mut out, "rows", &Value::Array(items.clone()), 0);
        }
        other => {
            out.push_str("<dl class=\"facts\">");
            render_fact(&mut out, "value", other, 0);
            out.push_str("</dl>\n");
        }
    }
    out.push_str("</article>");
    out
}

const STATUS_KEYS: [&str; 5] = [
    "analysis_complete",
    "analysis_incomplete_reasons",
    "result_complete",
    "result_incomplete_reasons",
    "matched",
];

fn render_document_object(out: &mut String, fields: &serde_json::Map<String, Value>) {
    render_status_strip(out, fields);
    // Scalars first as a fact list, then each compound field as a section,
    // then paging metadata last — the same reading order as the text view.
    let mut scalars: Vec<(&String, &Value)> = Vec::new();
    let mut compounds: Vec<(&String, &Value)> = Vec::new();
    for (key, value) in fields {
        if STATUS_KEYS.contains(&key.as_str()) || key == "page" {
            continue;
        }
        if is_scalar(value) {
            scalars.push((key, value));
        } else {
            compounds.push((key, value));
        }
    }
    if !scalars.is_empty() {
        out.push_str("<dl class=\"facts\">");
        for (key, value) in scalars {
            render_fact(out, key, value, 0);
        }
        out.push_str("</dl>\n");
    }
    for (key, value) in compounds {
        render_section(out, key, value, 0);
    }
    if let Some(page) = fields.get("page") {
        render_page(out, page);
    }
}

fn render_status_strip(out: &mut String, fields: &serde_json::Map<String, Value>) {
    let analysis = fields.get("analysis_complete").and_then(Value::as_bool);
    let result = fields.get("result_complete").and_then(Value::as_bool);
    let matched = fields.get("matched").and_then(Value::as_bool);
    if analysis.is_none() && result.is_none() && matched.is_none() {
        return;
    }
    out.push_str("<div class=\"status\">");
    if let Some(complete) = analysis {
        badge(out, "analysis", complete);
    }
    if let Some(complete) = result {
        badge(out, "result", complete);
    }
    if let Some(matched) = matched {
        let class = if matched { "ok" } else { "warn" };
        let _ = write!(
            out,
            "<span class=\"badge {class}\">filter {}</span>",
            if matched { "matched" } else { "no match" }
        );
    }
    out.push_str("</div>\n");
    for key in ["analysis_incomplete_reasons", "result_incomplete_reasons"] {
        if let Some(Value::Array(reasons)) = fields.get(key) {
            if reasons.is_empty() {
                continue;
            }
            let _ = write!(out, "<ul class=\"reasons\" data-kind=\"{}\">", escape(key));
            for reason in reasons {
                let _ = write!(out, "<li>{}</li>", escape(&scalar_text(reason)));
            }
            out.push_str("</ul>\n");
        }
    }
}

fn badge(out: &mut String, label: &str, complete: bool) {
    let class = if complete { "ok" } else { "warn" };
    let state = if complete { "complete" } else { "incomplete" };
    let _ = write!(out, "<span class=\"badge {class}\">{label} {state}</span>");
}

fn render_page(out: &mut String, page: &Value) {
    let Value::Object(fields) = page else {
        return;
    };
    out.push_str("<footer class=\"page\"><dl>");
    for (key, value) in fields {
        let _ = write!(
            out,
            "<div><dt>{}</dt><dd>{}</dd></div>",
            escape(&humanize(key)),
            escape(&scalar_text(value))
        );
    }
    out.push_str("</dl></footer>\n");
}

fn render_section(out: &mut String, key: &str, value: &Value, depth: usize) {
    let count = match value {
        Value::Array(items) => Some(items.len()),
        Value::Object(fields) => Some(fields.len()),
        _ => None,
    };
    let level = (depth + 2).min(6);
    let _ = write!(
        out,
        "<section class=\"group\"><h{level}>{}",
        escape(&humanize(key))
    );
    if let Some(count) = count {
        let _ = write!(out, " <span class=\"count\">{count}</span>");
    }
    let _ = writeln!(out, "</h{level}>");
    render_value(out, Some(key), value, depth + 1);
    out.push_str("</section>\n");
}

fn render_fact(out: &mut String, key: &str, value: &Value, depth: usize) {
    let _ = write!(out, "<div><dt>{}</dt><dd>", escape(&humanize(key)));
    render_value(out, Some(key), value, depth + 1);
    out.push_str("</dd></div>");
}

fn render_value(out: &mut String, key: Option<&str>, value: &Value, depth: usize) {
    match value {
        Value::Null => out.push_str("<span class=\"null\">—</span>"),
        Value::Bool(b) => {
            let _ = write!(out, "<span class=\"bool\">{b}</span>");
        }
        Value::Number(n) => {
            let _ = write!(out, "<span class=\"num\">{n}</span>");
        }
        Value::String(s) => render_string(out, key, s),
        Value::Array(items) => render_array(out, key, items, depth),
        Value::Object(fields) => render_object(out, fields, depth),
    }
}

fn render_string(out: &mut String, key: Option<&str>, text: &str) {
    if text.is_empty() {
        out.push_str("<span class=\"empty\">(empty)</span>");
        return;
    }
    if key == Some("severity") && crate::theme::severity_color(text).is_some() {
        let _ = write!(
            out,
            "<span class=\"badge severity sev-{}\">{}</span>",
            text.to_ascii_lowercase(),
            escape(text),
        );
        return;
    }
    if text.contains('\n') || key.is_some_and(is_code_key) {
        let _ = write!(out, "<pre><code>{}</code></pre>", escape(text));
    } else if key.is_some_and(is_identifier_key) {
        let _ = write!(out, "<code class=\"id\">{}</code>", escape(text));
    } else {
        out.push_str(&escape(text));
    }
}

fn render_array(out: &mut String, key: Option<&str>, items: &[Value], depth: usize) {
    if items.is_empty() {
        out.push_str("<span class=\"empty\">none</span>");
        return;
    }
    if items.iter().all(is_scalar) {
        if items
            .iter()
            .all(|item| !item.as_str().is_some_and(|s| s.contains('\n')))
        {
            out.push_str("<ul class=\"chips\">");
            for item in items {
                out.push_str("<li>");
                render_value(out, key, item, depth);
                out.push_str("</li>");
            }
            out.push_str("</ul>");
        } else {
            out.push_str("<ol class=\"lines\">");
            for item in items {
                out.push_str("<li>");
                render_value(out, key, item, depth);
                out.push_str("</li>");
            }
            out.push_str("</ol>");
        }
        return;
    }
    if items.iter().all(Value::is_object) {
        let records: Vec<&serde_json::Map<String, Value>> =
            items.iter().filter_map(Value::as_object).collect();
        if records_are_flat(&records) {
            render_table(out, &records, depth);
        } else {
            render_cards(out, &records, depth);
        }
        return;
    }
    out.push_str("<ol class=\"items\">");
    for item in items {
        out.push_str("<li>");
        render_value(out, key, item, depth);
        out.push_str("</li>");
    }
    out.push_str("</ol>");
}

fn render_object(out: &mut String, fields: &serde_json::Map<String, Value>, depth: usize) {
    if fields.is_empty() {
        out.push_str("<span class=\"empty\">none</span>");
        return;
    }
    out.push_str("<dl class=\"obj\">");
    for (key, value) in fields {
        if is_scalar(value) || matches!(value, Value::Array(items) if items.iter().all(is_scalar)) {
            render_fact(out, key, value, depth);
        }
    }
    out.push_str("</dl>");
    for (key, value) in fields {
        if !(is_scalar(value) || matches!(value, Value::Array(items) if items.iter().all(is_scalar))) {
            render_section(out, key, value, depth);
        }
    }
}

/// A record set renders as one table when every cell is a scalar, a short
/// list of scalars, or a one-level object of such values (a browse row's
/// `presentation` block flattens into `presentation · code` columns), and
/// the column count stays readable.
fn records_are_flat(records: &[&serde_json::Map<String, Value>]) -> bool {
    const MAX_COLUMNS: usize = 18;
    let columns = table_columns(records);
    if columns.len() > MAX_COLUMNS {
        return false;
    }
    records.iter().all(|record| {
        record.values().all(|value| match value {
            Value::Object(inner) => inner.values().all(is_table_cell),
            other => is_table_cell(other),
        })
    })
}

fn is_table_cell(value: &Value) -> bool {
    const MAX_LIST_CELL: usize = 12;
    match value {
        Value::Array(items) => items.len() <= MAX_LIST_CELL && items.iter().all(is_scalar),
        Value::Object(_) => false,
        _ => true,
    }
}

/// Identity columns a reader scans first. JSON objects serialize with
/// sorted keys, so without this a `defs` table would open with `column`
/// and bury `name` in the middle.
const LEADING_COLUMNS: [&str; 18] = [
    "finding_id",
    "flow_id",
    "group_id",
    "id",
    "rule_id",
    "edge_id",
    "taint_id",
    "name",
    "symbol",
    "function",
    "kind",
    "severity",
    "status",
    "file",
    "line",
    "column",
    "location",
    "code",
];

/// Column paths with identity columns first and every other column in
/// first-appearance order; a one-level nested object contributes
/// `parent/child` paths instead of one opaque column.
fn table_columns(records: &[&serde_json::Map<String, Value>]) -> Vec<(String, Option<String>)> {
    let mut columns = collected_table_columns(records);
    columns.sort_by_key(|(parent, child)| {
        let leaf = child.as_deref().unwrap_or(parent);
        let rank = LEADING_COLUMNS
            .iter()
            .position(|leading| leading == &leaf)
            .unwrap_or(LEADING_COLUMNS.len());
        // Nested presentation blocks follow the record's own fields.
        (child.is_some(), rank)
    });
    columns
}

fn collected_table_columns(records: &[&serde_json::Map<String, Value>]) -> Vec<(String, Option<String>)> {
    let mut columns: Vec<(String, Option<String>)> = Vec::new();
    for record in records {
        for (key, value) in record.iter() {
            match value {
                Value::Object(inner) => {
                    for child in inner.keys() {
                        let column = (key.clone(), Some(child.clone()));
                        if !columns.contains(&column) {
                            columns.push(column);
                        }
                    }
                }
                _ => {
                    let column = (key.clone(), None);
                    if !columns.contains(&column) {
                        columns.push(column);
                    }
                }
            }
        }
    }
    columns
}

fn render_table(out: &mut String, records: &[&serde_json::Map<String, Value>], depth: usize) {
    let columns = table_columns(records);
    out.push_str("<div class=\"scroll\"><table><thead><tr>");
    for (parent, child) in &columns {
        match child {
            Some(child) => {
                let _ = write!(
                    out,
                    "<th><span class=\"col-group\">{}</span> {}</th>",
                    escape(&humanize(parent)),
                    escape(&humanize(child))
                );
            }
            None => {
                let _ = write!(out, "<th>{}</th>", escape(&humanize(parent)));
            }
        }
    }
    out.push_str("</tr></thead><tbody>");
    for record in records {
        out.push_str("<tr>");
        for (parent, child) in &columns {
            out.push_str("<td>");
            let cell = match child {
                Some(child) => record.get(parent).and_then(|value| value.get(child)),
                None => record.get(parent),
            };
            match cell {
                Some(value) => render_value(out, Some(child.as_deref().unwrap_or(parent)), value, depth + 1),
                None => out.push_str("<span class=\"null\">—</span>"),
            }
            out.push_str("</td>");
        }
        out.push_str("</tr>");
    }
    out.push_str("</tbody></table></div>");
}

const CARD_TITLE_KEYS: [&str; 12] = [
    "finding_id",
    "flow_id",
    "group_id",
    "id",
    "rule_id",
    "name",
    "symbol",
    "query",
    "language",
    "path_id",
    "category",
    "file",
];

fn render_cards(out: &mut String, records: &[&serde_json::Map<String, Value>], depth: usize) {
    out.push_str("<ol class=\"cards\">");
    for (index, record) in records.iter().enumerate() {
        let _ = write!(
            out,
            "<li class=\"card\"><header><span class=\"ordinal\">{}</span>",
            index + 1
        );
        for key in CARD_TITLE_KEYS {
            if let Some(value) = record.get(key).filter(|v| is_scalar(v) && !v.is_null()) {
                let _ = write!(
                    out,
                    " <span class=\"title-fact\"><span class=\"k\">{}</span> <code>{}</code></span>",
                    escape(&humanize(key)),
                    escape(&scalar_text(value))
                );
            }
        }
        out.push_str("</header>");
        render_object(out, record, depth + 1);
        out.push_str("</li>");
    }
    out.push_str("</ol>");
}

fn is_scalar(value: &Value) -> bool {
    !matches!(value, Value::Array(_) | Value::Object(_))
}

fn is_code_key(key: &str) -> bool {
    matches!(
        key,
        "code"
            | "snippet"
            | "source"
            | "source_code"
            | "text"
            | "body"
            | "signature"
            | "line_text"
            | "call_code"
            | "value_text"
            | "matched_text"
            | "chain_display"
            | "content"
            | "statement"
            | "expression"
    ) || key.ends_with("_code")
        || key.ends_with("_snippet")
        || key.ends_with("_source")
}

fn is_identifier_key(key: &str) -> bool {
    key == "id"
        || key.ends_with("_id")
        || key.ends_with("_ids")
        || key == "cursor"
        || key == "next_cursor"
        || key == "file"
        || key.ends_with("_file")
        || key == "path"
        || key == "location"
        || key.ends_with("_location")
        || key == "func_id"
}

fn scalar_text(value: &Value) -> String {
    match value {
        Value::Null => "—".to_string(),
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

fn humanize(key: &str) -> String {
    key.replace('_', " ")
}

pub(crate) fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 8);
    for ch in text.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            _ => out.push(ch),
        }
    }
    out
}

const STYLESHEET: &str = r"
:root{color-scheme:light dark;--bg:#fbfbf9;--fg:#1f2421;--muted:#5f6b63;--line:#d8ddd6;--panel:#ffffff;--accent:#2f7d63;--ok:#2f7d63;--warn:#b25a1c;--code:#f1f3ef}
@media (prefers-color-scheme:dark){:root{--bg:#0f1512;--fg:#dfe6e0;--muted:#8c9a90;--line:#26302a;--panel:#141b17;--accent:#7cc7a8;--ok:#7cc7a8;--warn:#e7a66a;--code:#0b100d}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
main,.report-header{width:min(1280px,calc(100% - 32px));margin-inline:auto}
.report-header{padding:24px 0 12px;border-bottom:1px solid var(--line)}
.report-header h1{margin:0 0 6px;font-size:20px;font-weight:600}
.cmd-name{color:var(--accent)}
.cmd-line{display:block;color:var(--muted);font:12px/1.5 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;word-break:break-all}
main{padding:16px 0 40px}
.result{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:18px 20px;margin-bottom:18px}
.status{display:flex;flex-wrap:wrap;gap:8px;margin-bottom:12px}
.badge{display:inline-block;padding:2px 10px;border-radius:999px;font-size:12px;font-weight:600;border:1px solid var(--line)}
.badge.ok{color:var(--ok);border-color:var(--ok)}
.badge.warn{color:var(--warn);border-color:var(--warn)}
.severity{border-color:currentColor}
.sev-critical,.sev-error{color:#b52320}.sev-high,.sev-warning{color:#a34800}.sev-medium{color:#806100}.sev-low{color:#12658e}.sev-info,.sev-hint{color:#586474}
@media (prefers-color-scheme:dark){.sev-critical,.sev-error{color:#ff5f56}.sev-high,.sev-warning{color:#ffa64d}.sev-medium{color:#ebcb59}.sev-low{color:#6ac0e8}.sev-info,.sev-hint{color:#9eabba}}
.reasons{margin:0 0 12px;padding-left:20px;color:var(--warn)}
dl.facts,dl.obj{display:grid;grid-template-columns:max-content 1fr;gap:4px 16px;margin:0 0 12px}
dl.facts>div,dl.obj>div{display:contents}
dt{color:var(--muted);font-weight:500;white-space:nowrap}
dd{margin:0;min-width:0;overflow-wrap:anywhere}
section.group{margin:14px 0 0}
section.group h2,section.group h3,section.group h4,section.group h5,section.group h6{margin:0 0 8px;font-size:15px;font-weight:600}
.count{color:var(--muted);font-weight:400;font-size:13px}
.scroll{overflow-x:auto;border:1px solid var(--line);border-radius:8px}
table{border-collapse:collapse;width:100%;font-size:13px}
th,td{padding:6px 10px;border-bottom:1px solid var(--line);vertical-align:top;text-align:left}
th{background:var(--code);color:var(--muted);font-weight:600;white-space:nowrap;position:sticky;top:0}
tr:last-child td{border-bottom:0}
pre{margin:0;padding:8px 10px;background:var(--code);border:1px solid var(--line);border-radius:6px;overflow-x:auto;font:12.5px/1.5 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;white-space:pre}
td pre{max-width:640px}
code{font:12.5px/1.5 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
code.id{color:var(--accent)}
ul.chips{list-style:none;margin:0;padding:0;display:flex;flex-wrap:wrap;gap:4px 6px}
ul.chips li{background:var(--code);border:1px solid var(--line);border-radius:6px;padding:1px 7px;font-size:12.5px}
ol.cards{list-style:none;margin:0;padding:0;display:grid;gap:12px}
.card{border:1px solid var(--line);border-radius:8px;padding:12px 14px}
.card>header{display:flex;flex-wrap:wrap;gap:6px 14px;align-items:baseline;margin-bottom:8px;padding-bottom:6px;border-bottom:1px solid var(--line)}
.ordinal{color:var(--muted);font-weight:600}
.title-fact .k{color:var(--muted);font-size:12px}
.col-group{color:var(--muted);font-weight:400;font-size:11px}
ol.items,ol.lines{margin:0;padding-left:22px}
.null,.empty{color:var(--muted)}
footer.page{margin-top:16px;padding-top:10px;border-top:1px dashed var(--line);color:var(--muted);font-size:12.5px}
footer.page dl{display:flex;flex-wrap:wrap;gap:4px 18px;margin:0}
footer.page dl div{display:flex;gap:6px}
footer.page dt::after{content:':'}
@media (max-width:720px){dl.facts,dl.obj{grid-template-columns:1fr}dt{white-space:normal}}
";

#[cfg(test)]
mod tests {
    use super::{command_title, escape, render_fragment, HtmlDocumentContext};
    use serde_json::json;

    #[test]
    fn context_strips_the_sink_path_and_names_grouped_commands() {
        let ctx = HtmlDocumentContext::from_args(&[
            "--theme".to_string(),
            "moss".to_string(),
            "security".to_string(),
            "./src".to_string(),
            "taint-analysis".to_string(),
            "--html-output".to_string(),
            "/tmp/out.html".to_string(),
            "--no-progress".to_string(),
        ]);
        assert_eq!(ctx.title, "security taint-analysis");
        assert_eq!(
            ctx.command_line,
            "bonsai-ninja --theme moss security ./src taint-analysis --no-progress"
        );
        assert_eq!(command_title(&["defs".to_string(), "./src".to_string()]), "defs");
    }

    #[test]
    fn absolute_local_paths_never_reach_the_shared_report_header() {
        let ctx = HtmlDocumentContext::from_args(&[
            "defs".to_string(),
            "/Users/someone/private/repo".to_string(),
            "--output-path=/tmp/out.json".to_string(),
            "--name".to_string(),
            "verify".to_string(),
        ]);
        assert_eq!(ctx.title, "defs");
        assert!(
            !ctx.command_line.contains("/Users/someone"),
            "{}",
            ctx.command_line
        );
        assert!(ctx.command_line.contains("repo"), "{}", ctx.command_line);
        assert!(ctx.command_line.contains("--name verify"), "{}", ctx.command_line);

        let windows_ctx = HtmlDocumentContext::from_args(&[
            "defs".to_string(),
            r"C:\Users\someone\private\repo".to_string(),
        ]);
        assert!(
            !windows_ctx.command_line.contains(r"C:\Users\someone"),
            "{}",
            windows_ctx.command_line
        );
        assert!(
            windows_ctx.command_line.contains("repo"),
            "{}",
            windows_ctx.command_line
        );
    }

    #[test]
    fn fragment_renders_status_facts_tables_and_paging_from_the_canonical_object() {
        let value = json!({
            "analysis_complete": true,
            "analysis_incomplete_reasons": [],
            "result_complete": false,
            "result_incomplete_reasons": ["paged defs result incomplete: page 1 of 2"],
            "query": "verify",
            "rows": [
                {"name": "verify_token", "file": "auth.py", "line": 12, "presentation": {"code": "def verify_token(t):"}},
                {"name": "verify_user", "file": "auth.py", "line": 40, "presentation": {"code": "def verify_user(u):"}}
            ],
            "page": {"number": 1, "total_pages": 2, "next_cursor": "P:0badcafe"}
        });
        let html = render_fragment(&value);
        assert!(html.contains("analysis complete"));
        assert!(html.contains("result incomplete"));
        assert!(html.contains("paged defs result incomplete: page 1 of 2"));
        assert!(html.contains("<table>"));
        assert!(html.contains("verify_token"));
        assert!(html.contains("<pre><code>def verify_user(u):</code></pre>"));
        assert!(html.contains("<footer class=\"page\">"));
        assert!(html.contains("P:0badcafe"));
    }

    #[test]
    fn nested_records_render_as_cards_and_escape_markup() {
        let value = json!({
            "analysis_complete": true,
            "result_complete": true,
            "findings": [{
                "finding_id": "S:deadbeef",
                "severity": "high",
                "flows": [{"hops": [{"code": "x = req.args['q'] <script>"}]}]
            }]
        });
        let html = render_fragment(&value);
        assert!(html.contains("class=\"card\""));
        assert!(html.contains("S:deadbeef"));
        assert!(html.contains("&lt;script&gt;"));
        assert!(!html.contains("<script>"));
        assert_eq!(escape("a<b&c\"d"), "a&lt;b&amp;c&quot;d");
    }
}
