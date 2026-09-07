//! Every bundled frontend owns exact lexical string/comment body lengths.
//! Preserve Unicode scalars, whitespace, escapes and interpolation source.
//! No runtime decoding or raw-delimiter fallback may satisfy this contract.

// Decomposed e + combining acute deliberately distinguishes scalar counts
// from grapheme counts and catches accidental Unicode normalization.
#![allow(clippy::unicode_not_nfc)]

use bonsai_lang_api::{AdapterContext, DeclIndex, LanguageAdapter};
use std::{collections::BTreeSet, path::Path};

struct Fixture {
    language: &'static str,
    path: &'static str,
    source: &'static str,
    strings: &'static [(&'static str, &'static str)],
    comments: &'static [(&'static str, &'static str)],
}

const FIXTURES: &[Fixture] = &[
    Fixture {
        language: "c",
        path: "value.c",
        source: concat!(
            "void f(void) { char *a=\"\"; char *b=\"é🦀é\"; char *c=\"\\n\"; char *d=\" é \"; char *e=u8\"é\"; int x=L'é'; }\n",
            "//\n",
            "//é🦀é\n",
            "// é \n",
            "/**/\n",
            "/* é */\n",
            "/**é*/\n",
        ),
        strings: &[
            (r########""""########, r########""########),
            (r########""é🦀é""########, r########"é🦀é"########),
            (r########""\n""########, r########"\n"########),
            (r########"" é ""########, r########" é "########),
            (r########"u8"é""########, r########"é"########),
            (r########"L'é'"########, r########"é"########),
        ],
        comments: &[
            (r########"//"########, r########""########),
            (r########"//é🦀é"########, r########"é🦀é"########),
            (r########"// é "########, r########" é "########),
            (r########"/**/"########, r########""########),
            (r########"/* é */"########, r########" é "########),
            (r########"/**é*/"########, r########"é"########),
        ],
    },
    Fixture {
        language: "cpp",
        path: "value.cpp",
        source: concat!(
            "void f() { auto macro_piece=PREFIX \"é\"; auto a=\"\"; auto b=\"é🦀é\"; auto c=\"\\n\"; auto d=\" é \"; auto e=u8R\"tag(é)tag\"; auto g=R\"()\"; auto h=\"a\" /*inside*/ \"é\"; auto x=u'é'; }\n",
            "//\n",
            "//é🦀é\n",
            "// é \n",
            "/**/\n",
            "/* é */\n",
            "/**é*/\n",
        ),
        strings: &[
            (r########""""########, r########""########),
            (r########""é🦀é""########, r########"é🦀é"########),
            (r########""\n""########, r########"\n"########),
            (r########"" é ""########, r########" é "########),
            (r########"u8R"tag(é)tag""########, r########"é"########),
            (r########"R"()""########, r########""########),
            (r########""a" /*inside*/ "é""########, r########"aé"########),
            (r########"u'é'"########, r########"é"########),
            (r########"PREFIX "é""########, r########"é"########),
        ],
        comments: &[
            (r########"//"########, r########""########),
            (r########"//é🦀é"########, r########"é🦀é"########),
            (r########"// é "########, r########" é "########),
            (r########"/**/"########, r########""########),
            (r########"/* é */"########, r########" é "########),
            (r########"/**é*/"########, r########"é"########),
            (r########"/*inside*/"########, r########"inside"########),
        ],
    },
    Fixture {
        language: "csharp",
        path: "Value.cs",
        source: concat!(
            "class Value { byte[] n=\"é\"u8; byte[] o=\"\"\"é\"\"\"u8; byte[] p=@\"é\"u8; string a=\"\"; string b=\"é🦀é\"; string c=\"\\n\"; string d=\" é \"; string e=@\"\"; string f=@\"é\"\"é\"; string g=\"\"\"é\"\"\"; string h=\"\"\"\n",
            "é\n",
            "\"\"\"; string i=$\"a{v}é\"; string j=$@\"a{v}é\"; string k=@$\"a{v}é\"; string l=$$\"\"\"a{{v}}é\"\"\"; char m='é'; }\n",
            "//\n",
            "//é🦀é\n",
            "// é \n",
            "/**/\n",
            "/* é */\n",
            "/**é*/\n",
        ),
        strings: &[
            (r########""""########, r########""########),
            (r########""é🦀é""########, r########"é🦀é"########),
            (r########""\n""########, r########"\n"########),
            (r########"" é ""########, r########" é "########),
            (r########"@"""########, r########""########),
            (r########"@"é""é""########, r########"é""é"########),
            (r########""""é""""########, r########"é"########),
            (
                r########""""
é
""""########,
                r########"
é
"########,
            ),
            (r########"$"a{v}é""########, r########"a{v}é"########),
            (r########"$@"a{v}é""########, r########"a{v}é"########),
            (r########"@$"a{v}é""########, r########"a{v}é"########),
            (r########"$$"""a{{v}}é""""########, r########"a{{v}}é"########),
            (r########""é"u8"########, r########"é"########),
            (r########""""é"""u8"########, r########"é"########),
            (r########"@"é"u8"########, r########"é"########),
            (r########"'é'"########, r########"é"########),
        ],
        comments: &[
            (r########"//"########, r########""########),
            (r########"//é🦀é"########, r########"é🦀é"########),
            (r########"// é "########, r########" é "########),
            (r########"/**/"########, r########""########),
            (r########"/* é */"########, r########" é "########),
            (r########"/**é*/"########, r########"é"########),
        ],
    },
    Fixture {
        language: "dart",
        path: "value.dart",
        source: concat!(
            "var a=\"\"; var b=\"é🦀é\"; var c=\"\\n\"; var d=\" é \"; var e=r\"\"; var f=r'''é\\n'''; var g=\"\"\"é\"\"\"; var h=\"a${v}é\"; var i=\"a\" \"é\"; var j=\"\"\"\"\"\";\n",
            "///é\n",
            "//\n",
            "//é🦀é\n",
            "// é \n",
            "/**/\n",
            "/* é */\n",
            "/**é*/\n",
        ),
        strings: &[
            (r########""""########, r########""########),
            (r########""é🦀é""########, r########"é🦀é"########),
            (r########""\n""########, r########"\n"########),
            (r########"" é ""########, r########" é "########),
            (r########"r"""########, r########""########),
            (r########"r'''é\n'''"########, r########"é\n"########),
            (r########""""é""""########, r########"é"########),
            (r########""a${v}é""########, r########"a${v}é"########),
            (r########""a" "é""########, r########"aé"########),
            (r########""""""""########, r########""########),
        ],
        comments: &[
            (r########"//"########, r########""########),
            (r########"//é🦀é"########, r########"é🦀é"########),
            (r########"// é "########, r########" é "########),
            (r########"/**/"########, r########""########),
            (r########"/* é */"########, r########" é "########),
            (r########"/**é*/"########, r########"é"########),
            (r########"///é"########, r########"é"########),
        ],
    },
    Fixture {
        language: "elixir",
        path: "value.ex",
        source: concat!(
            "a=\"\"\n",
            "b=\"é🦀é\"\n",
            "c=\"\\n\"\n",
            "d=\" é \"\n",
            "e=\"a#{v}é\"\n",
            "f=\"\"\"\n",
            "é\n",
            "\"\"\"\n",
            "g='é'\n",
            "\n",
            "#\n",
            "#é🦀é\n",
            "# é \n",
        ),
        strings: &[
            (r########""""########, r########""########),
            (r########""é🦀é""########, r########"é🦀é"########),
            (r########""\n""########, r########"\n"########),
            (r########"" é ""########, r########" é "########),
            (r########""a#{v}é""########, r########"a#{v}é"########),
            (
                r########""""
é
""""########,
                r########"
é
"########,
            ),
            (r########"'é'"########, r########"é"########),
        ],
        comments: &[
            (r########"#"########, r########""########),
            (r########"#é🦀é"########, r########"é🦀é"########),
            (r########"# é "########, r########" é "########),
        ],
    },
    Fixture {
        language: "erlang",
        path: "value.erl",
        source: concat!(
            "-module(value).\n",
            "-define(STR(X), ??X).\n",
            "f() -> {\"\", \"é🦀é\", \"\\n\", \" é \", \"a\" \"é\", ~s(é), ~S\"\\n\", ~b[é], ~B{é}, ~<é>, ~s/é/, ~s|é|, ~s#é#, ~s`é`, ~s'é', \"\"\"\"\n",
            "é\n",
            "\"\"\"\", ~s\"\"\"\n",
            "é\n",
            "\"\"\"}.\n",
            "%\n",
            "%%é🦀é\n",
            "% é \n",
        ),
        strings: &[
            (r########""""########, r########""########),
            (r########""é🦀é""########, r########"é🦀é"########),
            (r########""\n""########, r########"\n"########),
            (r########"" é ""########, r########" é "########),
            (r########"??X"########, r########"X"########),
            (r########"~s(é)"########, r########"é"########),
            (r########"~S"\n""########, r########"\n"########),
            (r########"~b[é]"########, r########"é"########),
            (r########"~B{é}"########, r########"é"########),
            (r########"~<é>"########, r########"é"########),
            (r########"~s/é/"########, r########"é"########),
            (r########"~s|é|"########, r########"é"########),
            (r########"~s#é#"########, r########"é"########),
            (r########"~s`é`"########, r########"é"########),
            (r########"~s'é'"########, r########"é"########),
            (
                r########"""""
é
"""""########,
                r########"
é
"########,
            ),
            (
                r########"~s"""
é
""""########,
                r########"
é
"########,
            ),
        ],
        comments: &[
            (r########"%"########, r########""########),
            (r########"%%é🦀é"########, r########"é🦀é"########),
            (r########"% é "########, r########" é "########),
        ],
    },
    Fixture {
        language: "go",
        path: "value.go",
        source: concat!(
            "package value\n",
            "func f() { a:=\"\"; b:=\"é🦀é\"; c:=\"\\n\"; d:=\" é \"; e:=``; f:=`é\\n`; g:='é' }\n",
            "\n",
            "//\n",
            "//é🦀é\n",
            "// é \n",
            "/**/\n",
            "/* é */\n",
            "/**é*/\n",
        ),
        strings: &[
            (r########""""########, r########""########),
            (r########""é🦀é""########, r########"é🦀é"########),
            (r########""\n""########, r########"\n"########),
            (r########"" é ""########, r########" é "########),
            (r########"``"########, r########""########),
            (r########"`é\n`"########, r########"é\n"########),
            (r########"'é'"########, r########"é"########),
        ],
        comments: &[
            (r########"//"########, r########""########),
            (r########"//é🦀é"########, r########"é🦀é"########),
            (r########"// é "########, r########" é "########),
            (r########"/**/"########, r########""########),
            (r########"/* é */"########, r########" é "########),
            (r########"/**é*/"########, r########"é"########),
        ],
    },
    Fixture {
        language: "java",
        path: "Value.java",
        source: concat!(
            "class Value { String a=\"\"; String b=\"é🦀é\"; String c=\"\\n\"; String d=\" é \"; String e=\"\"\"\n",
            "é\n",
            "\"\"\"; String f=STR.\"a\\{v}é\"; char g='é'; }\n",
            "\n",
            "//\n",
            "//é🦀é\n",
            "// é \n",
            "/**/\n",
            "/* é */\n",
            "/**é*/\n",
        ),
        strings: &[
            (r########""""########, r########""########),
            (r########""é🦀é""########, r########"é🦀é"########),
            (r########""\n""########, r########"\n"########),
            (r########"" é ""########, r########" é "########),
            (
                r########""""
é
""""########,
                r########"
é
"########,
            ),
            (r########"STR."a\{v}é""########, r########"a\{v}é"########),
            (r########"'é'"########, r########"é"########),
        ],
        comments: &[
            (r########"//"########, r########""########),
            (r########"//é🦀é"########, r########"é🦀é"########),
            (r########"// é "########, r########" é "########),
            (r########"/**/"########, r########""########),
            (r########"/* é */"########, r########" é "########),
            (r########"/**é*/"########, r########"é"########),
        ],
    },
    Fixture {
        language: "javascript",
        path: "value.js",
        source: concat!(
            "#!/bin/js\n",
            "let a=\"\"; let b=\"é🦀é\"; let c=\"\\n\"; let d=\" é \"; let e=``; let f=`a${v}é`; let g=`\n",
            "é\n",
            "`;\n",
            "\n",
            "//\n",
            "//é🦀é\n",
            "// é \n",
            "/**/\n",
            "/* é */\n",
            "/**é*/\n",
        ),
        strings: &[
            (r########""""########, r########""########),
            (r########""é🦀é""########, r########"é🦀é"########),
            (r########""\n""########, r########"\n"########),
            (r########"" é ""########, r########" é "########),
            (r########"``"########, r########""########),
            (r########"`a${v}é`"########, r########"a${v}é"########),
            (
                r########"`
é
`"########,
                r########"
é
"########,
            ),
        ],
        comments: &[
            (r########"//"########, r########""########),
            (r########"//é🦀é"########, r########"é🦀é"########),
            (r########"// é "########, r########" é "########),
            (r########"/**/"########, r########""########),
            (r########"/* é */"########, r########" é "########),
            (r########"/**é*/"########, r########"é"########),
            (r########"#!/bin/js"########, r########"/bin/js"########),
        ],
    },
    Fixture {
        language: "typescript",
        path: "value.ts",
        source: concat!(
            "#!/bin/js\n",
            "let a=\"\"; let b=\"é🦀é\"; let c=\"\\n\"; let d=\" é \"; let e=``; let f=`a${v}é`; let g=`\n",
            "é\n",
            "`;\n",
            "\n",
            "//\n",
            "//é🦀é\n",
            "// é \n",
            "/**/\n",
            "/* é */\n",
            "/**é*/\n",
        ),
        strings: &[
            (r########""""########, r########""########),
            (r########""é🦀é""########, r########"é🦀é"########),
            (r########""\n""########, r########"\n"########),
            (r########"" é ""########, r########" é "########),
            (r########"``"########, r########""########),
            (r########"`a${v}é`"########, r########"a${v}é"########),
            (
                r########"`
é
`"########,
                r########"
é
"########,
            ),
        ],
        comments: &[
            (r########"//"########, r########""########),
            (r########"//é🦀é"########, r########"é🦀é"########),
            (r########"// é "########, r########" é "########),
            (r########"/**/"########, r########""########),
            (r########"/* é */"########, r########" é "########),
            (r########"/**é*/"########, r########"é"########),
            (r########"#!/bin/js"########, r########"/bin/js"########),
        ],
    },
    Fixture {
        language: "kotlin",
        path: "Value.kt",
        source: concat!(
            "val a=\"\"\n",
            "val b=\"é🦀é\"\n",
            "val c=\"\\n\"\n",
            "val d=\" é \"\n",
            "val e=\"\"\"\"\"\"\n",
            "val f=\"\"\"é\\n\"\"\"\n",
            "val g=\"a${v}é\"\n",
            "val h='é'\n",
            "\n",
            "//\n",
            "//é🦀é\n",
            "// é \n",
            "/**/\n",
            "/* é */\n",
            "/**é*/\n",
        ),
        strings: &[
            (r########""""########, r########""########),
            (r########""é🦀é""########, r########"é🦀é"########),
            (r########""\n""########, r########"\n"########),
            (r########"" é ""########, r########" é "########),
            (r########""""""""########, r########""########),
            (r########""""é\n""""########, r########"é\n"########),
            (r########""a${v}é""########, r########"a${v}é"########),
            (r########"'é'"########, r########"é"########),
        ],
        comments: &[
            (r########"//"########, r########""########),
            (r########"//é🦀é"########, r########"é🦀é"########),
            (r########"// é "########, r########" é "########),
            (r########"/**/"########, r########""########),
            (r########"/* é */"########, r########" é "########),
            (r########"/**é*/"########, r########"é"########),
        ],
    },
    Fixture {
        language: "lua",
        path: "value.lua",
        source: concat!(
            "#!/bin/lua\n",
            "local a=\"\"; local b=\"é🦀é\"; local c=\"\\n\"; local d=\" é \"; local e=[=[]=]; local f=[==[é\\n]==]\n",
            "--\n",
            "--é🦀é\n",
            "-- é \n",
            "--[==[é]==]\n",
            "---é\n",
        ),
        strings: &[
            (r########""""########, r########""########),
            (r########""é🦀é""########, r########"é🦀é"########),
            (r########""\n""########, r########"\n"########),
            (r########"" é ""########, r########" é "########),
            (r########"[=[]=]"########, r########""########),
            (r########"[==[é\n]==]"########, r########"é\n"########),
        ],
        comments: &[
            (r########"#!/bin/lua"########, r########"/bin/lua"########),
            (r########"--"########, r########""########),
            (r########"--é🦀é"########, r########"é🦀é"########),
            (r########"-- é "########, r########" é "########),
            (r########"--[==[é]==]"########, r########"é"########),
            (r########"---é"########, r########"é"########),
        ],
    },
    Fixture {
        language: "objc",
        path: "value.m",
        source: concat!(
            "void f(void) { id macro_piece=PREFIX @\"é\"; char *a=\"\"; char *b=\"é🦀é\"; char *c=\"\\n\"; char *d=\" é \"; id e=@\"\"; id g=@\"é\"; id h=@\"a\" @\"é\"; int i='é'; }\n",
            "\n",
            "//\n",
            "//é🦀é\n",
            "// é \n",
            "/**/\n",
            "/* é */\n",
            "/**é*/\n",
        ),
        strings: &[
            (r########""""########, r########""########),
            (r########""é🦀é""########, r########"é🦀é"########),
            (r########""\n""########, r########"\n"########),
            (r########"" é ""########, r########" é "########),
            (r########"@"""########, r########""########),
            (r########"@"é""########, r########"é"########),
            (r########"@"a" @"é""########, r########"aé"########),
            (r########"PREFIX @"é""########, r########"é"########),
            (r########"'é'"########, r########"é"########),
        ],
        comments: &[
            (r########"//"########, r########""########),
            (r########"//é🦀é"########, r########"é🦀é"########),
            (r########"// é "########, r########" é "########),
            (r########"/**/"########, r########""########),
            (r########"/* é */"########, r########" é "########),
            (r########"/**é*/"########, r########"é"########),
        ],
    },
    Fixture {
        language: "perl",
        path: "value.pl",
        source: concat!(
            "my $a=\"\"; my $b=\"é🦀é\"; my $c=\"\\n\"; my $d=\" é \"; my $e=q{}; my $f=q{é}; my $g=qq(a${v}é); my $h='é';\n",
            "\n",
            "#\n",
            "#é🦀é\n",
            "# é \n",
        ),
        strings: &[
            (r########""""########, r########""########),
            (r########""é🦀é""########, r########"é🦀é"########),
            (r########""\n""########, r########"\n"########),
            (r########"" é ""########, r########" é "########),
            (r########"q{}"########, r########""########),
            (r########"q{é}"########, r########"é"########),
            (r########"qq(a${v}é)"########, r########"a${v}é"########),
            (r########"'é'"########, r########"é"########),
        ],
        comments: &[
            (r########"#"########, r########""########),
            (r########"#é🦀é"########, r########"é🦀é"########),
            (r########"# é "########, r########" é "########),
        ],
    },
    Fixture {
        language: "php",
        path: "value.php",
        source: concat!(
            "<?php $a=\"\"; $b=\"é🦀é\"; $c=\"\\n\"; $d=\" é \"; $e=b\"é\"; $f=B'é'; $g=\"a{$v}é\"; $h=<<<TXT\n",
            "é{$v}\n",
            "TXT;\n",
            "$i=<<<TXT\n",
            "TXT;\n",
            "$j=<<<'TXT'\n",
            "é\n",
            "TXT;\n",
            "$k=<<<'TXT'\n",
            "TXT;\n",
            "\n",
            "//\n",
            "//é🦀é\n",
            "// é \n",
            "/**/\n",
            "/* é */\n",
            "/**é*/\n",
            "\n",
            "#\n",
            "#é🦀é\n",
            "# é \n",
        ),
        strings: &[
            (r########""""########, r########""########),
            (r########""é🦀é""########, r########"é🦀é"########),
            (r########""\n""########, r########"\n"########),
            (r########"" é ""########, r########" é "########),
            (r########"b"é""########, r########"é"########),
            (r########"B'é'"########, r########"é"########),
            (r########""a{$v}é""########, r########"a{$v}é"########),
            (
                r########"<<<TXT
é{$v}
TXT"########,
                r########"
é{$v}"########,
            ),
            (
                r########"<<<TXT
TXT"########,
                r########""########,
            ),
            (
                r########"<<<'TXT'
é
TXT"########,
                r########"
é"########,
            ),
            (
                r########"<<<'TXT'
TXT"########,
                r########""########,
            ),
        ],
        comments: &[
            (r########"//"########, r########""########),
            (r########"//é🦀é"########, r########"é🦀é"########),
            (r########"// é "########, r########" é "########),
            (r########"/**/"########, r########""########),
            (r########"/* é */"########, r########" é "########),
            (r########"/**é*/"########, r########"é"########),
            (r########"#"########, r########""########),
            (r########"#é🦀é"########, r########"é🦀é"########),
            (r########"# é "########, r########" é "########),
        ],
    },
    Fixture {
        language: "python",
        path: "value.py",
        source: concat!(
            "\"\"\"docé\"\"\"\n",
            "a=\"\"\n",
            "b=\"é🦀é\"\n",
            "c=\"\\n\"\n",
            "d=\" é \"\n",
            "e=r\"\"\"\"\"\"\n",
            "f=rb\"\"\"é\\n\"\"\"\n",
            "g=f\"a{v}é\"\n",
            "h=\"a\" \"é\"\n",
            "i=\"\"\"\n",
            "é\n",
            "\"\"\"\n",
            "\n",
            "#\n",
            "#é🦀é\n",
            "# é \n",
        ),
        strings: &[
            (r########""""########, r########""########),
            (r########""é🦀é""########, r########"é🦀é"########),
            (r########""\n""########, r########"\n"########),
            (r########"" é ""########, r########" é "########),
            (r########""""docé""""########, r########"docé"########),
            (r########"r"""""""########, r########""########),
            (r########"rb"""é\n""""########, r########"é\n"########),
            (r########"f"a{v}é""########, r########"a{v}é"########),
            (r########""a" "é""########, r########"aé"########),
            (
                r########""""
é
""""########,
                r########"
é
"########,
            ),
        ],
        comments: &[
            (r########"#"########, r########""########),
            (r########"#é🦀é"########, r########"é🦀é"########),
            (r########"# é "########, r########" é "########),
            (r########""""docé""""########, r########"docé"########),
        ],
    },
    Fixture {
        language: "ruby",
        path: "value.rb",
        source: concat!(
            "a=\"\"\n",
            "b=\"é🦀é\"\n",
            "c=\"\\n\"\n",
            "d=\" é \"\n",
            "e=%q{}\n",
            "f=%q{é\\n}\n",
            "g=\"a#{v}é\"\n",
            "h=\"a\" \"é\"\n",
            "i=<<~TXT\n",
            "é\n",
            "TXT\n",
            "=begin note\n",
            "é\n",
            "=end tail\n",
            "\n",
            "#\n",
            "#é🦀é\n",
            "# é \n",
        ),
        strings: &[
            (r########""""########, r########""########),
            (r########""é🦀é""########, r########"é🦀é"########),
            (r########""\n""########, r########"\n"########),
            (r########"" é ""########, r########" é "########),
            (r########"%q{}"########, r########""########),
            (r########"%q{é\n}"########, r########"é\n"########),
            (r########""a#{v}é""########, r########"a#{v}é"########),
            (r########""a" "é""########, r########"aé"########),
            (
                r########"
é
TXT"########,
                r########"
é
"########,
            ),
        ],
        comments: &[
            (r########"#"########, r########""########),
            (r########"#é🦀é"########, r########"é🦀é"########),
            (r########"# é "########, r########" é "########),
            (
                r########"=begin note
é
=end tail"########,
                r########" note
é
"########,
            ),
        ],
    },
    Fixture {
        language: "rust",
        path: "value.rs",
        source: concat!(
            "fn f() { let a=\"\"; let b=\"é🦀é\"; let c=\"\\n\"; let d=\" é \"; let e=r\"\"; let f=r###\"é\\n\"###; let g=br#\"\"#; let h=c\"é\"; let i='é'; let j=b'x'; }\n",
            "//\n",
            "//é🦀é\n",
            "// é \n",
            "/**/\n",
            "/* é */\n",
            "/**é*/\n",
            "///é\n",
            "//!é\n",
            "/*!é*/\n",
            "////é\n",
            "/*a/*é*/b*/\n",
        ),
        strings: &[
            (r########""""########, r########""########),
            (r########""é🦀é""########, r########"é🦀é"########),
            (r########""\n""########, r########"\n"########),
            (r########"" é ""########, r########" é "########),
            (r########"r"""########, r########""########),
            (r########"r###"é\n"###"########, r########"é\n"########),
            (r########"br#""#"########, r########""########),
            (r########"c"é""########, r########"é"########),
            (r########"'é'"########, r########"é"########),
            (r########"b'x'"########, r########"x"########),
        ],
        comments: &[
            (r########"//"########, r########""########),
            (r########"//é🦀é"########, r########"é🦀é"########),
            (r########"// é "########, r########" é "########),
            (r########"/**/"########, r########""########),
            (r########"/* é */"########, r########" é "########),
            (r########"/**é*/"########, r########"é"########),
            (
                r########"///é
"########,
                r########"é"########,
            ),
            (
                r########"//!é
"########,
                r########"é"########,
            ),
            (r########"/*!é*/"########, r########"é"########),
            (r########"////é"########, r########"//é"########),
            (r########"/*a/*é*/b*/"########, r########"a/*é*/b"########),
        ],
    },
    Fixture {
        language: "scala",
        path: "Value.scala",
        source: concat!(
            "object Value { val a=\"\"; val b=\"é🦀é\"; val c=\"\\n\"; val d=\" é \"; val e=\"\"\"\"\"\"; val f=\"\"\"é\\n\"\"\"; val g=s\"a${v}é\"; val h=raw\"\"; val i='é' }\n",
            "\n",
            "//\n",
            "//é🦀é\n",
            "// é \n",
            "/**/\n",
            "/* é */\n",
            "/**é*/\n",
        ),
        strings: &[
            (r########""""########, r########""########),
            (r########""é🦀é""########, r########"é🦀é"########),
            (r########""\n""########, r########"\n"########),
            (r########"" é ""########, r########" é "########),
            (r########""""""""########, r########""########),
            (r########""""é\n""""########, r########"é\n"########),
            (r########"s"a${v}é""########, r########"a${v}é"########),
            (r########"raw"""########, r########""########),
            (r########"'é'"########, r########"é"########),
        ],
        comments: &[
            (r########"//"########, r########""########),
            (r########"//é🦀é"########, r########"é🦀é"########),
            (r########"// é "########, r########" é "########),
            (r########"/**/"########, r########""########),
            (r########"/* é */"########, r########" é "########),
            (r########"/**é*/"########, r########"é"########),
        ],
    },
    Fixture {
        language: "swift",
        path: "value.swift",
        source: concat!(
            "let a=\"\"\n",
            "let b=\"é🦀é\"\n",
            "let c=\"\\n\"\n",
            "let d=\" é \"\n",
            "let e=##\"\"##\n",
            "let f=#\"é\\n\"#\n",
            "let g=\"a\\(v)é\"\n",
            "let h=#\"a\\#(v)é\"#\n",
            "let i=\"\"\"\n",
            "é\n",
            "\"\"\"\n",
            "\n",
            "//\n",
            "//é🦀é\n",
            "// é \n",
            "/**/\n",
            "/* é */\n",
            "/**é*/\n",
        ),
        strings: &[
            (r########""""########, r########""########),
            (r########""é🦀é""########, r########"é🦀é"########),
            (r########""\n""########, r########"\n"########),
            (r########"" é ""########, r########" é "########),
            (r########"##""##"########, r########""########),
            (r########"#"é\n"#"########, r########"é\n"########),
            (r########""a\(v)é""########, r########"a\(v)é"########),
            (r########"#"a\#(v)é"#"########, r########"a\#(v)é"########),
            (
                r########""""
é
""""########,
                r########"
é
"########,
            ),
        ],
        comments: &[
            (r########"//"########, r########""########),
            (r########"//é🦀é"########, r########"é🦀é"########),
            (r########"// é "########, r########" é "########),
            (r########"/**/"########, r########""########),
            (r########"/* é */"########, r########" é "########),
            (r########"/**é*/"########, r########"é"########),
        ],
    },
];

fn extract(adapter: &dyn LanguageAdapter, fixture: &Fixture) -> DeclIndex {
    let vfs = bonsai_vfs::Vfs::new();
    let file = vfs.write(Path::new(fixture.path), fixture.source);
    let diagnostics = parking_lot::RwLock::new(bonsai_diagnostics::DiagnosticSink::default());
    adapter.extract_declarations(
        file,
        &AdapterContext {
            vfs: &vfs,
            diagnostics: &diagnostics,
            tree_provider: None,
            workspace_root: None,
        },
    )
}

#[test]
fn all_twenty_adapters_emit_exact_lexical_lengths_for_the_complete_inventory() {
    let adapters = bonsai_adapters::all_adapters();
    let bundled: BTreeSet<_> = adapters.iter().map(|a| a.language_id().as_str()).collect();
    let covered: BTreeSet<_> = FIXTURES.iter().map(|f| f.language).collect();
    assert_eq!(covered, bundled);
    assert_eq!(covered.len(), 20);
    assert_eq!("é🦀é".chars().count(), 4, "scalar count, not bytes or graphemes");

    for fixture in FIXTURES {
        let adapter = adapters
            .iter()
            .find(|a| a.language_id().as_str() == fixture.language)
            .unwrap();
        let grammar = adapter.tree_sitter_language().expect("bundled grammar");
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&grammar).unwrap();
        let tree = parser.parse(fixture.source, None).unwrap();
        assert!(
            !tree.root_node().has_error(),
            "{}: fixture must be parser-complete: {}",
            fixture.language,
            tree.root_node().to_sexp()
        );
        let handler = adapter
            .grammar_handler_for_path(Path::new(fixture.path))
            .expect("grammar contract");
        let string_len = handler
            .string_content_len
            .expect("every bundled string inventory needs a body hook");
        let comment_len = handler
            .comment_content_len
            .expect("every bundled comment inventory needs a body hook");
        let mut seen = BTreeSet::new();
        let mut pending = vec![tree.root_node()];
        // Check every declared node, including literals nested in interpolation
        // which the outer string inventory intentionally coalesces.
        while let Some(node) = pending.pop() {
            if node.is_named() && handler.string_literal_kinds.contains(&node.kind()) {
                assert!(
                    string_len(node, fixture.source.as_bytes()).is_some(),
                    "{}: unknown valid string {}: {:?}",
                    fixture.language,
                    node.kind(),
                    node.utf8_text(fixture.source.as_bytes()).unwrap()
                );
                seen.insert(node.kind());
            }
            if handler.comment_kinds.contains(&node.kind()) {
                assert!(
                    comment_len(node, fixture.source.as_bytes()).is_some(),
                    "{}: unknown valid comment {}: {:?}",
                    fixture.language,
                    node.kind(),
                    node.utf8_text(fixture.source.as_bytes()).unwrap()
                );
                seen.insert(node.kind());
            }
            pending.extend(node.children(&mut node.walk()));
        }
        for kind in handler
            .string_literal_kinds
            .iter()
            .chain(handler.comment_kinds.iter())
        {
            // Erlang retains a named multi_string wrapper in its symbol table,
            // but the current parser flattens it into individual string nodes.
            // The adjacent-string fixture above checks that emitted inventory.
            if fixture.language == "erlang" && *kind == "multi_string" {
                continue;
            }
            assert!(
                seen.contains(kind),
                "{}: gauntlet is missing declared inventory kind {kind}",
                fixture.language
            );
        }

        let index = extract(adapter.as_ref(), fixture);
        assert!(
            !index.strings.is_empty() && !index.comments.is_empty(),
            "{}: empty inventory",
            fixture.language
        );
        for literal in &index.strings {
            assert!(
                literal.content_len.is_some(),
                "{}: emitted unknown string {:?}",
                fixture.language,
                literal.text
            );
        }
        for comment in &index.comments {
            assert!(
                comment.content_len.is_some(),
                "{}: emitted unknown comment {:?}",
                fixture.language,
                comment.text
            );
        }
        for (source, body) in fixture.strings {
            let matches: Vec<_> = index
                .strings
                .iter()
                .filter(|literal| {
                    fixture
                        .source
                        .get(literal.span.start as usize..literal.span.end as usize)
                        == Some(*source)
                })
                .collect();
            assert!(
                !matches.is_empty(),
                "{}: missing literal {source:?}",
                fixture.language
            );
            for literal in matches {
                assert_eq!(
                    literal.content_len,
                    Some(body.chars().count()),
                    "{}: lexical body of {source:?}",
                    fixture.language
                );
            }
        }
        for (source, body) in fixture.comments {
            let matches: Vec<_> = index
                .comments
                .iter()
                .filter(|comment| {
                    fixture
                        .source
                        .get(comment.span.start as usize..comment.span.end as usize)
                        == Some(*source)
                })
                .collect();
            assert!(
                !matches.is_empty(),
                "{}: missing comment {source:?}",
                fixture.language
            );
            for comment in matches {
                assert_eq!(
                    comment.content_len,
                    Some(body.chars().count()),
                    "{}: lexical body of {source:?}",
                    fixture.language
                );
            }
        }
        // Persisted compiler facts must retain both Some(0) and Unicode counts.
        let round_trip: DeclIndex = serde_json::from_value(serde_json::to_value(&index).unwrap()).unwrap();
        assert_eq!(round_trip.strings, index.strings);
        assert_eq!(round_trip.comments, index.comments);
    }
}

#[test]
fn anonymous_type_keywords_are_not_string_literals() {
    let fixtures = [
        Fixture {
            language: "php",
            path: "types.php",
            source: "<?php function f(string $value): string { return 'string'; }",
            strings: &[],
            comments: &[],
        },
        Fixture {
            language: "typescript",
            path: "types.ts",
            source:
                "interface Value { kind: string; } function f(value: string): string { return \"string\"; }",
            strings: &[],
            comments: &[],
        },
    ];
    let adapters = bonsai_adapters::all_adapters();
    for fixture in fixtures {
        let adapter = adapters
            .iter()
            .find(|adapter| adapter.language_id().as_str() == fixture.language)
            .unwrap();
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&adapter.tree_sitter_language().unwrap())
            .unwrap();
        let tree = parser.parse(fixture.source, None).unwrap();
        assert!(!tree.root_node().has_error());
        let handler = adapter.grammar_handler().unwrap();
        let mut pending = vec![tree.root_node()];
        let mut anonymous_collisions = 0;
        while let Some(node) = pending.pop() {
            if !node.is_named() && handler.string_literal_kinds.contains(&node.kind()) {
                anonymous_collisions += 1;
            }
            pending.extend(node.children(&mut node.walk()));
        }
        assert!(
            anonymous_collisions > 0,
            "fixture must exercise the grammar-name collision"
        );
        let index = extract(adapter.as_ref(), &fixture);
        assert_eq!(
            index.strings.len(),
            1,
            "{}: {:?}",
            fixture.language,
            index.strings
        );
        let literal = &index.strings[0];
        assert_eq!(literal.content_len, Some(6));
        assert!(matches!(literal.text.as_str(), "\"string\"" | "'string'"));
        assert_eq!(
            &fixture.source[literal.span.start as usize..literal.span.end as usize],
            literal.text
        );
    }
}

#[test]
fn php_multiline_categories_use_the_body_without_losing_complete_literal_spans() {
    use bonsai_lang_api::StringCategory;

    let fixture = Fixture {
        language: "php",
        path: "categories.php",
        source: "<?php\n$a = <<<'URL'\nhttps://example.test\nURL;\n$b = <<<'PATH'\n/var/data\nPATH;\n$c = <<<SQL\nSELECT name FROM records\nSQL;\n$d = <<<'EMPTY'\nEMPTY;\n$e = <<<URL\nhttps://example.test\nURL;\n",
        strings: &[],
        comments: &[],
    };
    let adapter = bonsai_adapters::all_adapters()
        .into_iter()
        .find(|adapter| adapter.language_id().as_str() == "php")
        .unwrap();
    let index = extract(adapter.as_ref(), &fixture);
    let cases = [
        (
            "<<<'URL'\nhttps://example.test\nURL",
            "\nhttps://example.test",
            StringCategory::Url,
        ),
        ("<<<'PATH'\n/var/data\nPATH", "\n/var/data", StringCategory::Path),
        (
            "<<<SQL\nSELECT name FROM records\nSQL",
            "\nSELECT name FROM records",
            StringCategory::Sql,
        ),
        ("<<<'EMPTY'\nEMPTY", "", StringCategory::Generic),
        (
            "<<<URL\nhttps://example.test\nURL",
            "\nhttps://example.test",
            StringCategory::Url,
        ),
    ];
    assert_eq!(index.strings.len(), cases.len());
    for (text, body, category) in cases {
        let literal = index.strings.iter().find(|literal| literal.text == text).unwrap();
        assert_eq!(literal.category, category, "{text}");
        assert_eq!(literal.content_len, Some(body.chars().count()), "{text}");
        assert_eq!(
            &fixture.source[literal.span.start as usize..literal.span.end as usize],
            text
        );
    }
}

#[test]
fn an_unconfigured_body_hook_never_substitutes_raw_length_or_drops_the_fact() {
    let adapter = bonsai_adapters::all_adapters()
        .into_iter()
        .find(|adapter| adapter.language_id().as_str() == "javascript")
        .unwrap();
    let mut handler = *adapter.grammar_handler().unwrap();
    handler.string_content_len = None;
    handler.comment_content_len = None;
    let source = "const value = \"\"; /**/";
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&adapter.tree_sitter_language().unwrap())
        .unwrap();
    let tree = parser.parse(source, None).unwrap();
    let file = bonsai_common::FileId::new(0);
    let strings = bonsai_lang_api::kit::extract_string_literals(&tree, file, source.as_bytes(), &handler);
    let comments = bonsai_lang_api::kit::extract_comments(&tree, file, source.as_bytes(), &handler);
    assert_eq!(strings.len(), 1);
    assert_eq!(comments.len(), 1);
    assert_eq!(strings[0].content_len, None);
    assert_eq!(comments[0].content_len, None);
}
