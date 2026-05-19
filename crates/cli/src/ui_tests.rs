use super::syntect_cache;
use crate::theme::Theme;

/// Every supported language must have a syntect
/// grammar available, otherwise `inspect` / `refs` render source
/// as plain uniform text. Caught Swift / Kotlin / TypeScript
/// missing when we were on syntect's defaults — now we pull from
/// `two_face` which bundles bat's full set.
#[test]
fn every_supported_lang_has_a_syntect_grammar() {
    let cache = syntect_cache();
    for adapter in bonsai_adapters::all_adapters() {
        let name = adapter.language_id().as_str();
        let extensions = adapter.file_extensions();
        assert!(
            !extensions.is_empty(),
            "adapter `{name}` must declare at least one file extension",
        );
        for ext in extensions {
            let found = cache.syntaxes.find_syntax_by_extension(ext);
            assert!(
                found.is_some(),
                "no syntect grammar registered for .{ext} ({name}) — \
             `inspect`'s inlined source will render uniformly for this language"
            );
        }
    }
}

/// Every theme's `syntect_theme_name()` must resolve to a theme
/// actually present in the cache. Guards against copy-paste typos
/// in the chrome↔syntax mapping (e.g. renaming "Gruvbox Dark" to
/// "gruvbox-dark" in `Theme::syntect_theme_name` without updating
/// the insert key in `syntect_cache`).
#[test]
fn every_theme_has_a_registered_syntax_theme() {
    let cache = syntect_cache();
    for theme in [Theme::EarthyDark, Theme::Dracula, Theme::RetroAmber, Theme::Moss] {
        let name = theme.syntect_theme_name();
        assert!(
            cache.themes.themes.contains_key(name),
            "theme {theme:?} points at syntax theme `{name}` which \
             isn't in the SyntectCache — `inspect` will fall back \
             to an arbitrary theme for this chrome preset"
        );
    }
}

/// Mid-file one-line snippets in every supported language must
/// produce at least two distinct token colors. Catches the class
/// of bug where a grammar needs a file preamble to reach its
/// proper parse state (PHP inside HTML, Solidity inside a
/// contract / function scope) and otherwise emits every token
/// in the default foreground. The `syntax_preamble_for` helper
/// in [`SyntectCache::highlight`] runs that preamble through the
/// highlighter first; this test proves it actually fires.
#[test]
fn mid_file_snippets_produce_distinct_token_colors() {
    let cache = syntect_cache();
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
        ("sol", "require(amount > 0, \"z\");"),
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
             color(s) — syntect is falling back to the default fg. \
             Likely needs a `syntax_preamble_for` entry to reach its \
             normal parse state.",
            distinct.len(),
        );
    }
}

/// Render a small snippet through every theme and confirm each
/// produces DIFFERENT highlighted output. Catches silent
/// mis-wires where two themes both end up using the fallback.
#[test]
fn themes_produce_distinct_output() {
    let cache = syntect_cache();
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
