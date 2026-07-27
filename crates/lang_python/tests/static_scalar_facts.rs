use bonsai_db::AnalyzerDb;
use bonsai_lang_api::{LanguageRegistry, StaticScalarValue};
use bonsai_vfs::Vfs;
use std::sync::Arc;

#[test]
fn keyword_argument_scalars_are_decoded_from_python_syntax() {
    let vfs = Arc::new(Vfs::new());
    let file = vfs.write(
        "configured.py".to_string(),
        Arc::<str>::from(
            r#"
configured = factory(
    disabled=False,
    enabled=True,
    mode="strict",
    missing=None,
)
"#,
        ),
    );
    let registry = Arc::new(LanguageRegistry::new());
    registry.register(Arc::new(bonsai_lang_python::PythonAdapter::new()));
    let db = AnalyzerDb::new(vfs, registry);
    let index = db.decl_index(file).expect("Python declaration index");

    let values: Vec<_> = index
        .call_argument_values
        .iter()
        .filter_map(|fact| {
            fact.static_value
                .clone()
                .map(|value| (fact.argument_index, value))
        })
        .collect();
    assert_eq!(
        values,
        vec![
            (0, StaticScalarValue::Boolean(false)),
            (1, StaticScalarValue::Boolean(true)),
            (2, StaticScalarValue::String("strict".to_string())),
            (3, StaticScalarValue::Null),
        ],
        "{:#?}",
        index.call_argument_values
    );
}
