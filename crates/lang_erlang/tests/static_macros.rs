use bonsai_lang_api::StaticScalarValue;
use std::sync::Arc;

fn index(source: &str) -> Arc<bonsai_lang_api::DeclIndex> {
    let runner = bonsai_conformance::ConformanceRunner::new(
        Arc::new(bonsai_lang_erlang::ErlangAdapter::new()),
        vec![("values.erl".to_string(), source.to_string())],
    );
    let workspace = runner.workspace();
    let file = workspace.vfs().all_files()[0];
    workspace.db().decl_index(file).expect("Erlang compiler index")
}

#[test]
fn unique_scalar_macros_are_immutable_compiler_values() {
    let index = index(
        "-module(values).\n-define(BASE, \"/srv/data\").\n-export([read/1]).\nread(Name) -> filename:join(?BASE, Name).\n",
    );
    assert!(index.assignment_values.iter().any(|fact| {
        fact.target.as_deref() == Some("BASE")
            && fact.target_is_immutable
            && fact.static_value == Some(StaticScalarValue::String("/srv/data".to_string()))
    }));
}

#[test]
fn repeated_or_dynamic_macros_do_not_claim_static_provenance() {
    let index = index(
        "-module(values).\n-define(BASE, \"/srv/one\").\n-define(BASE, dynamic()).\n-export([read/1]).\nread(Name) -> filename:join(?BASE, Name).\n",
    );
    assert!(index
        .assignment_values
        .iter()
        .all(|fact| fact.target.as_deref() != Some("BASE")));
}
