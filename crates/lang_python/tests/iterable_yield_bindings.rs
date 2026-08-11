use bonsai_db::AnalyzerDb;
use bonsai_lang_api::{AssignValueKind, FlowEvent, LanguageRegistry};
use bonsai_vfs::Vfs;
use std::sync::Arc;

#[test]
fn tuple_iterable_yield_refinement_reuses_the_generic_tuple_place() {
    let vfs = Arc::new(Vfs::new());
    vfs.write(
        "sample.py".to_string(),
        Arc::<str>::from(
            "def expand(parts):\n    for index, part in enumerate(parts):\n        consume(part)\n",
        ),
    );
    let registry = Arc::new(LanguageRegistry::new());
    registry.register(Arc::new(bonsai_lang_python::PythonAdapter::new()));
    let db = AnalyzerDb::new(vfs, registry);
    let global = db.global_index();
    let declaration = global
        .all_files()
        .flat_map(|file| global.decls_in(file))
        .find(|decl| decl.name == "expand")
        .expect("expand declaration");
    let part_bindings = declaration
        .flow_events
        .iter()
        .filter_map(|event| match event {
            FlowEvent::Assign {
                target,
                source_names,
                value_kind,
                ..
            } if target == "part" => Some((source_names.as_slice(), *value_kind)),
            _ => None,
        })
        .collect::<Vec<_>>();

    assert!(
        part_bindings.iter().any(|(sources, kind)| {
            *kind == Some(AssignValueKind::YieldResult)
                && sources.iter().any(|source| source == "__bonsai_tuple_result_1")
        }),
        "the yield alternative must target the same tuple projection as the generic binding: {part_bindings:?}"
    );
    assert!(
        !part_bindings
            .iter()
            .any(|(sources, kind)| *kind == Some(AssignValueKind::YieldResult) && sources.is_empty()),
        "a tuple yield refinement must not create a second clean scalar write: {part_bindings:?}"
    );
}
