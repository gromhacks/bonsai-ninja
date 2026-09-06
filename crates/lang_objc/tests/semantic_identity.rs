use bonsai_lang_api::{DeclIndex, DeclKind, FlowEvent};
use std::sync::Arc;

fn lower(source: &str) -> Arc<DeclIndex> {
    let workspace = bonsai_testkit::workspace_with(
        vec![Arc::new(bonsai_lang_objc::ObjCAdapter::new())],
        &[("Identity.m", source)],
    );
    let file = workspace.vfs().all_files()[0];
    workspace.db().decl_index(file).expect("Objective-C declarations")
}

#[test]
fn c_helpers_are_not_objective_c_initializers() {
    let index = lower("void init(void) {}\nvoid initWithData(id value) {}\n");
    for name in ["init", "initWithData"] {
        let decl = index.defs.iter().find(|decl| decl.name == name).unwrap();
        assert_eq!(decl.kind, DeclKind::Function, "{name}");
    }
}

#[test]
fn initializer_family_respects_selector_signature_and_explicit_attribute() {
    let index = lower(
        r#"
@interface Box
- (id)init;
- (id)_initOther:(id)value;
- (id)initialValue;
- (void)initWithLogging:(id)value;
- (id)initWithThing:(id)value __attribute__((objc_method_family(none)));
- (id)create:(id)value __attribute__((objc_method_family(init)));
+ (id)initWithClass;
@end
"#,
    );
    for (name, expected) in [
        ("init", DeclKind::Constructor),
        ("_initOther", DeclKind::Constructor),
        ("initialValue", DeclKind::Method),
        ("initWithLogging", DeclKind::Method),
        ("initWithThing", DeclKind::Method),
        ("create", DeclKind::Constructor),
        ("initWithClass", DeclKind::Method),
    ] {
        let decl = index.defs.iter().find(|decl| decl.name == name).unwrap();
        assert_eq!(decl.kind, expected, "{name}");
    }
}

#[test]
fn method_attribute_identifiers_cannot_replace_parameter_bindings() {
    let index = lower(
        r#"
@interface Box
- (id)transform:(id)value __attribute__((objc_method_family(none)));
@end
"#,
    );
    let method = index.defs.iter().find(|decl| decl.name == "transform").unwrap();
    assert_eq!(method.params, ["value"]);
}

#[test]
fn initializer_calls_use_the_receivers_declaration_not_an_unrelated_selector() {
    use bonsai_lang_api::CallKind;
    let index = lower(
        r#"
@interface Builder
- (id)create:(id)value __attribute__((objc_method_family(init)));
@end
@interface Reader
- (id)create:(id)value;
- (id)initWithThing:(id)value __attribute__((objc_method_family(none)));
@end
void run(id input) {
  [[Builder alloc] create:input];
  [[Reader alloc] create:input];
  [[Reader alloc] initWithThing:input];
}
"#,
    );
    let run = index.defs.iter().find(|decl| decl.name == "run").unwrap();
    for (owner, selector, expected) in [
        ("Builder", "create", CallKind::Constructor),
        ("Reader", "create", CallKind::Method),
        ("Reader", "initWithThing", CallKind::Method),
    ] {
        let kind = run
            .flow_events
            .iter()
            .find_map(|event| match event {
                FlowEvent::Call {
                    name,
                    call_kind,
                    receiver_types,
                    ..
                } if name.ends_with(selector) && receiver_types.iter().any(|receiver| receiver == owner) => {
                    Some(*call_kind)
                }
                _ => None,
            })
            .unwrap();
        assert_eq!(kind, expected, "{owner}.{selector}");
    }
}

#[test]
fn dictionary_fields_require_the_exact_assignment_value_and_key() {
    let index = lower(
        r#"
void run(id input) {
  id direct = @{ @"key": input };
  id padded = @{ @" key ": input };
  id wrapped = replace(@{ @"key": input });
}
"#,
    );
    let run = index.defs.iter().find(|decl| decl.name == "run").unwrap();
    let fields = run
        .flow_events
        .iter()
        .filter_map(|event| match event {
            FlowEvent::Assign { target, .. } if target.contains(".@") => Some(target.as_str()),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert!(fields.contains(&"direct.@key"), "{fields:?}");
    assert!(
        !fields.contains(&"padded.@key"),
        "whitespace changes key identity: {fields:?}"
    );
    assert!(
        !fields.contains(&"wrapped.@key"),
        "a wrapper result is not its argument: {fields:?}"
    );
}
