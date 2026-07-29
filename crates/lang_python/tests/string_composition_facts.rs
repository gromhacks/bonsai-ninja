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
