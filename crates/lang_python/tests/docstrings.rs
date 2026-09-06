use bonsai_db::AnalyzerDb;
use bonsai_lang_api::{CommentKind, LanguageRegistry};
use bonsai_vfs::Vfs;
use std::sync::Arc;

#[test]
fn docstrings_ignore_leading_comments_and_require_plain_string_values() {
    let source = r#"# module comment
"module docs"
class Example:
    # class comment
    ("class docs")
    def method(self):
        # function comment
        "function " "docs"
def formatted():
    f"not a docstring"
def binary():
    b"not a docstring"
def tuple_value():
    "not a docstring", "either"
"#;
    let vfs = Arc::new(Vfs::new());
    let file = vfs.write("docs.py", source);
    let registry = Arc::new(LanguageRegistry::new());
    registry.register(Arc::new(bonsai_lang_python::PythonAdapter::new()));
    let db = AnalyzerDb::new(vfs, registry);
    let index = db.decl_index(file).expect("Python declaration index");
    let docs = index
        .comments
        .iter()
        .filter(|comment| comment.kind == CommentKind::Doc)
        .collect::<Vec<_>>();
    assert_eq!(docs.len(), 3, "{docs:#?}");
    assert!(
        docs.iter()
            .all(|comment| !comment.text.contains("not a docstring")),
        "{docs:#?}"
    );
    assert!(docs.iter().any(|comment| comment.text.contains("module docs")));
    assert!(docs.iter().any(|comment| comment.text.contains("class docs")));
    assert!(docs.iter().any(|comment| comment.text.contains("function ")));
}

#[test]
fn only_leading_bare_strings_are_python_docstrings() {
    let vfs = Arc::new(Vfs::new());
    let file = vfs.write(
        "docs.py".to_string(),
        Arc::<str>::from(
            r#""module docs"

def documented():
    'single-line function docs'
    value = "ordinary string"
    return value

async def async_documented():
    "async function docs"
    return None

def not_documented():
    value = "first assignment is not a docstring"
    return value
"#,
        ),
    );
    let registry = Arc::new(LanguageRegistry::new());
    registry.register(Arc::new(bonsai_lang_python::PythonAdapter::new()));
    let db = AnalyzerDb::new(vfs, registry);
    let index = db.decl_index(file).expect("Python declaration index");

    let docs: Vec<_> = index
        .comments
        .iter()
        .filter(|comment| comment.kind == CommentKind::Doc)
        .map(|comment| comment.text.as_str())
        .collect();
    assert_eq!(docs.len(), 3, "{:#?}", index.comments);
    assert!(docs.iter().any(|text| text.contains("module docs")));
    assert!(docs.iter().any(|text| text.contains("single-line function docs")));
    assert!(docs.iter().any(|text| text.contains("async function docs")));
    assert!(docs.iter().all(|text| !text.contains("ordinary string")));
    assert!(docs
        .iter()
        .all(|text| !text.contains("first assignment is not a docstring")));
}
