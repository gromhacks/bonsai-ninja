use bonsai_lang_api::{StaticScalarValue, StaticStringMapEntry};
use std::sync::Arc;

fn index(source: &str) -> Arc<bonsai_lang_api::DeclIndex> {
    let runner = bonsai_conformance::ConformanceRunner::new(
        Arc::new(bonsai_lang_elixir::ElixirAdapter::new()),
        vec![("values.ex".to_string(), source.to_string())],
    );
    let workspace = runner.workspace();
    let file = workspace.vfs().all_files()[0];
    workspace.db().decl_index(file).expect("Elixir compiler index")
}

#[test]
fn unique_module_scalars_and_complete_string_maps_are_immutable_facts() {
    let index = index(
        r#"defmodule Values do
  @base "/srv/data"
  @choices %{"first" => "alpha", "second" => "beta"}
  def choose(key), do: Map.get(@choices, key, "fallback")
end
"#,
    );
    assert!(index.assignment_values.iter().any(|fact| {
        fact.target.as_deref() == Some("base")
            && fact.target_is_immutable
            && fact.static_value == Some(StaticScalarValue::String("/srv/data".to_string()))
    }));
    assert!(index.static_string_maps.iter().any(|map| {
        map.target == "choices"
            && map.target_is_immutable
            && map.entries
                == [
                    StaticStringMapEntry {
                        key: "first".to_string(),
                        value: "alpha".to_string(),
                    },
                    StaticStringMapEntry {
                        key: "second".to_string(),
                        value: "beta".to_string(),
                    },
                ]
    }));
}

#[test]
fn repeated_or_dynamic_module_values_fail_closed() {
    let index = index(
        r#"defmodule Values do
  @base "/srv/one"
  @base "/srv/two"
  @choices %{"first" => runtime_value()}
  def choose(key), do: Map.get(@choices, key, "fallback")
end
"#,
    );
    assert!(index
        .assignment_values
        .iter()
        .all(|fact| fact.target.as_deref() != Some("base")));
    assert!(index.static_string_maps.iter().all(|map| map.target != "choices"));
}
