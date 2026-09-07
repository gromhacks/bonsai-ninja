use bonsai_db::AnalyzerDb;
use bonsai_lang_api::{LanguageRegistry, StringCompositionPart};
use bonsai_vfs::Vfs;
use std::sync::Arc;

fn python_index(source: &str) -> Arc<bonsai_lang_api::DeclIndex> {
    let vfs = Arc::new(Vfs::new());
    let file = vfs.write("url_guard.py".to_string(), Arc::<str>::from(source));
    let registry = Arc::new(LanguageRegistry::new());
    registry.register(Arc::new(bonsai_lang_python::PythonAdapter::new()));
    AnalyzerDb::new(vfs, registry)
        .decl_index(file)
        .expect("Python declaration index")
}

#[test]
fn url_reconstruction_is_lowered_from_python_syntax() {
    let index = python_index(
        r#"
def rebuild(parsed):
    return "https://" + parsed.hostname + (parsed.path or "/")
"#,
    );
    assert_eq!(index.string_compositions.len(), 1, "{index:#?}");
    assert_eq!(index.string_compositions[0].dynamic_anchor_span, None);
    assert_eq!(
        index.string_compositions[0].parts,
        vec![
            StringCompositionPart::Literal {
                value: "https://".to_string(),
            },
            StringCompositionPart::Place {
                place: "parsed.hostname".to_string(),
            },
            StringCompositionPart::PlaceOrLiteral {
                place: "parsed.path".to_string(),
                fallback: "/".to_string(),
            },
        ]
    );
}

#[test]
fn adjacent_literals_inside_parenthesized_concatenation_are_one_static_part() {
    let source = r#"
def query(term):
    sql = ("SELECT id FROM products "
           "WHERE name = '" + term + "'")
    return sql
"#;
    let index = python_index(source);
    assert_eq!(index.string_compositions.len(), 1, "{index:#?}");
    let anchor = index.string_compositions[0]
        .dynamic_anchor_span
        .expect("the one dynamic operand must retain its exact compiler span");
    assert_eq!(
        source.get(anchor.start as usize..anchor.end as usize),
        Some("term")
    );
    assert_eq!(
        index.string_compositions[0].parts,
        vec![
            StringCompositionPart::Literal {
                value: "SELECT id FROM products WHERE name = '".to_string(),
            },
            StringCompositionPart::Place {
                place: "term".to_string(),
            },
            StringCompositionPart::Literal {
                value: "'".to_string(),
            },
        ]
    );
}

#[test]
fn unsupported_non_concatenating_returns_do_not_emit_compositions() {
    let index = python_index(
        r#"
def formatting(parsed):
    return f"https://{parsed.hostname}{parsed.path or '/'}"

def arithmetic(parsed):
    return parsed.port + 1
"#,
    );
    assert!(
        index.string_compositions.is_empty(),
        "{:#?}",
        index.string_compositions
    );
}

#[test]
fn direct_call_arguments_retain_complete_string_composition_spans() {
    let source = r#"
def example(value):
    consume("prefix:" + value)
    consume("prefix:" + fetch())
    consume(value + 1)
"#;
    let index = python_index(source);
    assert_eq!(index.string_compositions.len(), 2, "{index:#?}");
    for composition in &index.string_compositions {
        assert!(
            index
                .call_argument_values
                .iter()
                .any(|argument| { argument.argument_span == composition.value_span }),
            "composition must join the canonical argument directory"
        );
        assert!(
            matches!(composition.parts.first(), Some(StringCompositionPart::Literal { value }) if value == "prefix:")
        );
        assert!(
            source[composition.value_span.start as usize..composition.value_span.end as usize]
                .starts_with("\"prefix:\" + ")
        );
    }
    assert!(index
        .string_compositions
        .iter()
        .any(|fact| matches!(fact.parts.last(), Some(StringCompositionPart::Place { .. }))));
    assert!(index
        .string_compositions
        .iter()
        .any(|fact| matches!(fact.parts.last(), Some(StringCompositionPart::Call { .. }))));
}
