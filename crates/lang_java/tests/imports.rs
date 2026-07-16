use bonsai_db::AnalyzerDb;
use bonsai_lang_api::LanguageRegistry;
use bonsai_vfs::Vfs;
use std::sync::Arc;

#[test]
fn imports_are_lowered_from_java_syntax_nodes() {
    let vfs = Arc::new(Vfs::new());
    let file = vfs.write(
        "Imports.java".to_string(),
        Arc::<str>::from(
            r#"
import java.util.List;
import java.util.concurrent.*;
import static org.example.Router.route;
import static org.example.Constants.*;

class Imports {}
"#,
        ),
    );
    let registry = Arc::new(LanguageRegistry::new());
    registry.register(Arc::new(bonsai_lang_java::JavaAdapter::new()));
    let db = AnalyzerDb::new(vfs, registry);

    let imports = db.import_index(file).expect("Java import index");
    let facts: Vec<_> = imports
        .imports
        .iter()
        .map(|spec| {
            (
                spec.module.as_str(),
                spec.alias.as_deref(),
                spec.original_name.as_deref(),
                spec.is_wildcard,
            )
        })
        .collect();

    assert_eq!(
        facts,
        vec![
            ("java.util.List", Some("List"), None, false),
            ("java.util.concurrent", None, None, true),
            ("org.example.Router", Some("route"), Some("route"), false),
            ("org.example.Constants", None, None, true),
        ]
    );
    assert!(imports.imports.iter().all(|spec| spec.span.file == file));
}
