// Run with: cargo test --release -p bonsai-ninja-lang-api --test grammar_inspector -- --nocapture
use bonsai_lang_api::kit::language_from_pack;
use tree_sitter::Parser;

fn dump(node: tree_sitter::Node<'_>, depth: usize, src: &[u8]) {
    let indent = "  ".repeat(depth);
    let text = std::str::from_utf8(&src[node.byte_range()]).unwrap_or("");
    let preview = text.chars().take(40).collect::<String>().replace('\n', " ");
    let mut field: Option<String> = None;
    if let Some(parent) = node.parent() {
        for i in 0..parent.named_child_count() {
            if let Ok(idx) = u32::try_from(i) {
                if let Some(c) = parent.named_child(idx) {
                    if c.id() == node.id() {
                        if let Some(name) = parent.field_name_for_child(idx) {
                            field = Some(name.to_string());
                        }
                        break;
                    }
                }
            }
        }
    }
    let f = field.map(|s| format!(" [field={s}]")).unwrap_or_default();
    println!("{indent}{kind}{f} {preview:?}", kind = node.kind());
    for i in 0..node.named_child_count() {
        if let Ok(idx) = u32::try_from(i) {
            if let Some(c) = node.named_child(idx) {
                dump(c, depth + 1, src);
            }
        }
    }
}

#[test]
fn dump_typed_param_trees() {
    let cases = [
        ("kotlin", "fun handle(name: String) {}"),
        ("typescript", "function handle(name: string) {}"),
        ("csharp", "class App { void Handle(string name) {} }"),
        ("dart", "class App { void handle(String name) {} }"),
        ("php", "<?php\nfunction handle(string $name) {}"),
        ("cpp", "void handle(int code) {}"),
        ("c", "void handle(int code) {}"),
        ("objc", "void handle(NSString *name) {}"),
    ];
    for (lang, src) in cases {
        println!("=== {lang} ===");
        let language = match language_from_pack(lang) {
            Ok(l) => l,
            Err(e) => {
                println!("  err: {e}");
                continue;
            }
        };
        let mut parser = Parser::new();
        if parser.set_language(&language).is_err() {
            println!("  set_language failed");
            continue;
        }
        let Some(tree) = parser.parse(src, None) else {
            println!("  parse failed");
            continue;
        };
        dump(tree.root_node(), 0, src.as_bytes());
        println!();
    }
}
