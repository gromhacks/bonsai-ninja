//! Quick debug tool: parse a file with a language pack and dump its
//! tree-sitter AST. Used to investigate what node kinds a grammar
//! produces for specific syntax constructs.
//!
//! Run with:
//!   cargo run --example dump_tree -- <lang> <file>
//! e.g.
//!   cargo run --example dump_tree -- scala /tmp/sctree.scala
use std::env;
use std::fs;
use tree_sitter::{Node, Parser};

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        eprintln!("usage: dump_tree <lang> <file>");
        std::process::exit(1);
    }
    let lang = &args[1];
    let path = &args[2];
    let src = fs::read_to_string(path).expect("read file");
    let ts_lang = bonsai_lang_api::kit::language_from_pack(lang).expect("language pack");
    let mut parser = Parser::new();
    parser.set_language(&ts_lang).expect("set language");
    let tree = parser.parse(&src, None).expect("parse");
    dump(tree.root_node(), src.as_bytes(), 0);
}

fn dump(n: Node<'_>, src: &[u8], depth: usize) {
    let indent = "  ".repeat(depth);
    let text = if n.child_count() == 0 {
        let t = std::str::from_utf8(&src[n.byte_range()]).unwrap_or("?");
        format!(" '{}'", t.replace('\n', "\\n"))
    } else {
        String::new()
    };
    println!("{}{}{}", indent, n.kind(), text);
    let mut cursor = n.walk();
    for child in n.named_children(&mut cursor) {
        dump(child, src, depth + 1);
    }
}
