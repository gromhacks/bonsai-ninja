use bonsai_lang_api::{ConditionEquality, ConditionExpressionFact, StaticScalarValue, StringCompositionPart};
use std::sync::Arc;

fn index(source: &str) -> Arc<bonsai_lang_api::DeclIndex> {
    let runner = bonsai_conformance::ConformanceRunner::new(
        Arc::new(bonsai_lang_perl::PerlAdapter::new()),
        vec![("values.pl".to_string(), source.to_string())],
    );
    let workspace = runner.workspace();
    let file = workspace.vfs().all_files()[0];
    workspace.db().decl_index(file).expect("Perl compiler index")
}

#[test]
fn factory_arguments_and_path_boundary_are_exact_compiler_facts() {
    let index = index(
        r#"use XML::LibXML;
use Cwd qw(abs_path);
my $parser = XML::LibXML->new("expand_entities", 0, "no_network", 1);
my $root = abs_path("/srv/data");
my $boundary = $root . "/";
my $path = abs_path(File::Spec->catfile($root, $name));
if (index($path, $boundary) == 0) { open(my $fh, '<', $path); }
"#,
    );
    assert!(
        index.assignment_values.iter().any(|fact| {
            fact.target.as_deref() == Some("$parser")
                && fact.exact_static_call_args.as_deref()
                    == Some(
                        &[
                            StaticScalarValue::String("expand_entities".to_string()),
                            StaticScalarValue::Boolean(false),
                            StaticScalarValue::String("no_network".to_string()),
                            StaticScalarValue::Boolean(true),
                        ][..],
                    )
        }),
        "assignments={:#?}\narguments={:#?}",
        index.assignment_values,
        index.call_argument_values
    );
    assert!(
        index.string_compositions.iter().any(|fact| {
            fact.target.as_deref() == Some("$boundary")
                && matches!(
                    fact.parts.as_slice(),
                    [StringCompositionPart::Place { place }, StringCompositionPart::Literal { value }]
                        if place == "$root" && value == "/"
                )
        }),
        "{:#?}",
        index.string_compositions
    );
    assert!(
        index.branch_conditions.iter().any(|fact| {
            matches!(
                fact.expression.as_ref(),
                Some(ConditionExpressionFact::Equality {
                    relation: ConditionEquality::Equal,
                    left,
                    right,
                    ..
                }) if left.direct_call_span.is_some()
                    && right.static_value == Some(StaticScalarValue::Boolean(false))
            )
        }),
        "{:#?}",
        index.branch_conditions
    );
}

#[test]
fn dynamic_factory_argument_and_non_concatenation_do_not_claim_exact_values() {
    let index = index(
        r#"use XML::LibXML;
my $flag = runtime_flag();
my $parser = XML::LibXML->new("expand_entities", $flag);
my $name = <STDIN>;
my $root = abs_path($name);
my $value = $root + 1;
"#,
    );
    assert!(index
        .assignment_values
        .iter()
        .any(|fact| { fact.target.as_deref() == Some("$parser") && fact.exact_static_call_args.is_none() }));
    assert!(
        index
            .assignment_values
            .iter()
            .any(|fact| fact.target.as_deref() == Some("$root") && fact.exact_static_call_args.is_none()),
        "{:#?}",
        index.assignment_values
    );
    assert!(index.string_compositions.is_empty());
}

#[test]
fn readline_assignment_retains_the_exact_filehandle_value() {
    let index = index("my $line = <STDIN>;\n");
    let mut found = false;
    for decl in &index.defs {
        bonsai_lang_api::for_each_flow_event(&decl.flow_events, &mut |event| {
            if matches!(
                event,
                bonsai_lang_api::FlowEvent::Assign {
                    target,
                    source_name: Some(source),
                    source_names,
                    value_kind: Some(bonsai_lang_api::AssignValueKind::Compound),
                    ..
                } if target == "$line"
                    && source == "STDIN"
                    && source_names == &["STDIN".to_string()]
            ) {
                found = true;
            }
        });
    }
    assert!(
        found,
        "Perl <HANDLE> syntax must lower to an exact compiler value: {:#?}",
        index.defs
    );
}
