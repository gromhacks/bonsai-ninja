use crate::syntax_highlight::syntax_highlight_cache;
use crate::theme::Theme;

fn styled_ui(theme: Theme, colors: bool) -> super::Ui {
    super::Ui {
        colors,
        palette: theme.palette(),
        theme,
    }
}

#[test]
fn severity_colors_are_distinct_and_theme_independent() {
    let levels = ["critical", "high", "medium", "low", "info"];
    let reference = styled_ui(Theme::Moss, true);
    let colored = levels.map(|level| reference.severity(level));
    let codes: std::collections::BTreeSet<_> = colored
        .iter()
        .map(|value| value.split('m').next().unwrap())
        .collect();
    assert_eq!(codes.len(), 5);
    for theme in [Theme::Moss, Theme::Dracula, Theme::EarthyDark, Theme::RetroAmber] {
        let u = styled_ui(theme, true);
        let plain = styled_ui(theme, false);
        for level in levels {
            assert_eq!(u.severity(level), reference.severity(level));
            assert_eq!(plain.severity(level), level);
            assert!(u.severity(level).contains("\x1b["));
        }
        assert_eq!(plain.severity("unknown"), "unknown");
        assert_ne!(u.render_identity(), plain.render_identity());
    }
    assert!(reference.severity("critical").contains("255;95;86"));
    assert!(reference.severity("high").contains("255;166;77"));
    assert!(reference.severity("medium").contains("235;203;89"));
    assert_ne!(
        reference.render_identity(),
        styled_ui(Theme::Dracula, true).render_identity()
    );
}

#[test]
fn adaptive_tables_keep_long_labels_and_unexpected_extra_cells() {
    let u = styled_ui(Theme::Moss, false);
    let mut table = u.table(&["callee text", "caller function", "location", "code"]);
    table.set_width(80);
    table.add_row(vec!["execute", "handler", "app.py:1:1", "execute(value)"]);
    assert!(table.to_string().contains("caller function"));
    table.add_row(vec!["a", "b", "c", "d", "EXTRA"]);
    assert!(table.to_string().contains("EXTRA"));
}

#[test]
fn dense_tables_reflow_without_losing_fields_or_splitting_pinned_ids() {
    let u = styled_ui(Theme::Moss, false);
    let mut table = u.table_pinned(
        &["rule", "severity", "location", "message", "category"],
        &["rule"],
    );
    let id = "python.some_provider.a_deliberately_long_copyable_security_rule_identifier";
    table.add_row(vec![
        id,
        "critical",
        "src/app.py:19:4",
        "Unsafe input reaches this operation",
        "command-injection",
    ]);
    table.set_width(80);
    let narrow = table.to_string();
    for expected in [
        id,
        "critical",
        "src/app.py:19:4",
        "Unsafe input reaches this operation",
        "command-injection",
    ] {
        assert!(narrow.contains(expected), "missing {expected}: {narrow}");
    }
    assert!(narrow
        .lines()
        .any(|line| line.trim_start().starts_with("severity")));
    assert!(!narrow.contains("\x1b["));
    table.set_width(180);
    let wide = table.to_string();
    assert!(wide.contains('─'));
    assert_ne!(narrow, wide);
}

#[test]
fn result_headings_use_correct_singular_and_plural_labels() {
    let u = styled_ui(Theme::Moss, false);
    assert_eq!(
        u.result_heading("calls", 1, "call site", "call sites"),
        "calls — 1 call site"
    );
    assert_eq!(
        u.result_heading("calls", 0, "call site", "call sites"),
        "calls — 0 call sites"
    );
}

#[test]
fn html_severity_badges_preserve_canonical_values_and_escape_unknowns() {
    let result = crate::html::render_fragment(&serde_json::json!({
        "rows": [
            {"severity": "critical"}, {"severity": "high"}, {"severity": "medium"},
            {"severity": "low"}, {"severity": "info"}, {"severity": "<script>"}
        ]
    }));
    for level in ["critical", "high", "medium", "low", "info"] {
        assert!(result.contains(&format!("sev-{level}\">{level}</span>")));
    }
    assert!(result.contains("&lt;script&gt;"));
    assert!(!result.contains("<script>"));
}

/// Every supported language must expose its production Tree-sitter grammar.
#[test]
fn every_supported_lang_has_a_highlight_configuration() {
    let cache = syntax_highlight_cache();
    for adapter in bonsai_adapters::all_adapters() {
        let name = adapter.language_id().as_str();
        let extensions = adapter.file_extensions();
        assert!(
            !extensions.is_empty(),
            "adapter `{name}` must declare at least one file extension",
        );
        for ext in extensions {
            let found = cache.syntax_for_extension(ext);
            assert!(
                found.is_some(),
                "no Tree-sitter grammar registered for .{ext} ({name}) — \
                 `inspect`'s inlined source will render uniformly for this language"
            );
        }
    }
}

#[test]
fn tsx_highlighting_uses_the_tsx_grammar_variant() {
    let language = syntax_highlight_cache()
        .syntax_for_extension("tsx")
        .expect("TSX grammar");
    let mut parser = tree_sitter::Parser::new();
    parser.set_language(language).expect("set TSX grammar");
    let tree = parser
        .parse("const view = <Widget value={input}/>;", None)
        .expect("parse TSX snippet");
    assert!(
        !tree.root_node().has_error(),
        "syntax highlighting must not parse TSX with the plain TypeScript grammar"
    );
}

/// Mid-file one-line snippets in every supported language must
/// produce at least two distinct token colors. This catches a grammar fragment
/// that parses but exposes no useful semantic node classes.
#[test]
fn mid_file_snippets_produce_distinct_token_colors() {
    let cache = syntax_highlight_cache();
    // One realistic snippet per language, representative of what
    // the `calls` / `vars` tables inline into the code column.
    let cases = [
        ("c", "int x = foo(bar);"),
        ("cpp", "std::string s = q.exec();"),
        ("cs", "var x = Sink(token);"),
        ("dart", "var x = Process.run('ping', [input]);"),
        ("erl", "Y = lists:map(fun sink/1, [X])."),
        ("ex", "System.cmd(\"ping\", [input])"),
        ("go", "x := exec.Command(\"ping\", token)"),
        ("java", "String s = obj.method(arg);"),
        ("js", "const x = require('fs').readFileSync(p);"),
        ("kt", "val x = conn.createStatement().executeQuery(q)"),
        ("lua", "local r = os.execute(\"ping \" .. cmd)"),
        ("m", "NSString *s = [obj method:arg];"),
        ("pl", "my $x = system(\"ping \", $cmd);"),
        ("php", "$stmt->execute([$userId]);"),
        ("py", "cursor.execute(\"SELECT\", (user_id,))"),
        ("rb", "@db.execute(\"SELECT\", [token])"),
        ("rs", "let x = Command::new(\"sh\").arg(\"-c\").output();"),
        ("scala", "val x = stmt.executeQuery(q)"),
        ("swift", "let s = sqlite3_prepare_v2(db, q, -1, &stmt, nil)"),
        ("ts", "const x: Buffer = execSync('ping ' + cmd);"),
    ];
    for (ext, code) in cases {
        let rendered = cache.highlight(code, ext, Theme::Moss);
        // Count the distinct 24-bit foreground codes emitted.
        // Form: `\x1b[38;2;R;G;Bm`. Skip the trailing `\x1b[0m`.
        let mut distinct = std::collections::BTreeSet::new();
        for chunk in rendered.split("\x1b[38;2;") {
            if let Some(end) = chunk.find('m') {
                let code = &chunk[..end];
                if code.split(';').count() == 3 {
                    distinct.insert(code.to_string());
                }
            }
        }
        assert!(
            distinct.len() >= 2,
            "`.{ext}` snippet `{code}` produced only {} distinct token \
             color(s) — the Tree-sitter CST is not classifying the fragment.",
            distinct.len(),
        );
    }
}

/// Render a small snippet through every theme and confirm each
/// produces DIFFERENT highlighted output. Catches silent
/// mis-wires where two themes both end up using the fallback.
#[test]
fn themes_produce_distinct_output() {
    let cache = syntax_highlight_cache();
    let code =
        "fn hello(x: i32) -> String {\n    let s = \"hi\"; // note\n    return format!(\"{}\", x);\n}\n";
    let outputs: Vec<_> = [Theme::EarthyDark, Theme::Dracula, Theme::RetroAmber, Theme::Moss]
        .iter()
        .map(|t| cache.highlight(code, "rs", *t))
        .collect();
    for (i, a) in outputs.iter().enumerate() {
        for (j, b) in outputs.iter().enumerate().skip(i + 1) {
            assert_ne!(
                a, b,
                "themes #{i} and #{j} produced identical syntax output — \
                 one is silently falling back to the other"
            );
        }
    }
}
