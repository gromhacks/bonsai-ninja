use crate::syntax_highlight::syntax_highlight_cache;
use crate::theme::Theme;

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
