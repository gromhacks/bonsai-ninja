use bonsai_lang_api::{
    CharacterClass, CharacterConstraintDomain, CharacterConstraintOutput, LanguageAdapter,
};
use std::sync::Arc;

fn index(source: &str) -> bonsai_lang_api::DeclIndex {
    let adapter: Arc<dyn LanguageAdapter> = Arc::new(bonsai_lang_python::PythonAdapter::new());
    let ws = bonsai_testkit::workspace_with(vec![adapter], &[("guards.py", source)]);
    let file = *ws.db().vfs().all_files().first().expect("fixture file");
    (*ws.db().decl_index(file).expect("Python declaration index")).clone()
}

#[test]
fn comprehension_allowlist_lowers_to_exact_alphabet() {
    let index = index(
        r#"
def clean(q):
    safe = "".join(ch for ch in q if ch.isalnum() or ch == " ")[:64]
    return safe
"#,
    );
    let [fact] = index.character_constraints.as_slice() else {
        panic!(
            "expected one character constraint: {:#?}",
            index.character_constraints
        );
    };
    assert_eq!(fact.input_place, "q");
    assert_eq!(fact.input_param_index, Some(0));
    assert_eq!(
        fact.output,
        CharacterConstraintOutput::Assignment {
            target: "safe".to_string()
        }
    );
    assert_eq!(
        fact.domain,
        CharacterConstraintDomain::AllowOnly {
            classes: vec![CharacterClass::Alphanumeric],
            exact_characters: vec![" ".to_string()],
        }
    );
}

#[test]
fn formatted_string_assignment_preserves_exact_delimiter_context() {
    use bonsai_lang_api::StringCompositionPart;

    let index = index(
        r#"
def query(q):
    safe = "".join(ch for ch in q if ch.isalnum())
    sql = f"SELECT * FROM users WHERE name ILIKE '%{safe}%'"
    return execute(sql)
"#,
    );
    let composition = index
        .string_compositions
        .iter()
        .find(|composition| composition.target.as_deref() == Some("sql"))
        .unwrap_or_else(|| {
            panic!(
                "missing formatted-string composition: {:#?}",
                index.string_compositions
            )
        });
    assert_eq!(
        composition.parts,
        [
            StringCompositionPart::Literal {
                value: "SELECT * FROM users WHERE name ILIKE '%".to_string(),
            },
            StringCompositionPart::Place {
                place: "safe".to_string(),
            },
            StringCompositionPart::Literal {
                value: "%'".to_string(),
            },
        ]
    );
}

#[test]
fn helper_call_in_concatenation_has_exact_callee_span() {
    let source = r#"
def cleaned(value):
    return value

def header(filename):
    value = 'attachment; filename="' + cleaned(filename) + '"'
    return value
"#;
    let index = index(source);
    let fact = index
        .string_compositions
        .iter()
        .find(|fact| fact.target.as_deref() == Some("value"))
        .unwrap_or_else(|| panic!("missing composition: {:#?}", index.string_compositions));
    assert!(matches!(
        fact.parts.as_slice(),
        [
            bonsai_lang_api::StringCompositionPart::Literal { .. },
            bonsai_lang_api::StringCompositionPart::Call { .. },
            bonsai_lang_api::StringCompositionPart::Literal { .. }
        ]
    ));
    let call_span = match &fact.parts[1] {
        bonsai_lang_api::StringCompositionPart::Call { span } => *span,
        _ => unreachable!(),
    };
    let helper = index
        .defs
        .iter()
        .find(|decl| decl.name == "header")
        .expect("header decl")
        .flow_events
        .iter()
        .find_map(|event| match event {
            bonsai_lang_api::FlowEvent::Call { span, name, .. } if name == "cleaned" => Some(*span),
            _ => None,
        })
        .expect("cleaned call");
    assert_eq!(call_span, helper);
}

#[test]
fn comprehension_constraint_rejects_conjunction_and_unconstrained_body() {
    for source in [
        r#"
def bad(q):
    return "".join(ch for ch in q if ch.isalnum() and ch != "x")
"#,
        r#"
def bad(q):
    return "".join(ch + "'" for ch in q if ch.isalnum())
"#,
    ] {
        let index = index(source);
        assert!(
            index.character_constraints.is_empty(),
            "unsupported shape must fail closed: {:#?}",
            index.character_constraints
        );
    }
}

#[test]
fn compiled_regex_substitution_lowers_excluded_characters() {
    let index = index(
        r#"
import re
_UNSAFE = re.compile(r'[\r\n"\\]')

def safe_filename(filename):
    return _UNSAFE.sub("_", filename)
"#,
    );
    let [fact] = index.character_constraints.as_slice() else {
        panic!(
            "expected one character constraint: {:#?}",
            index.character_constraints
        );
    };
    assert_eq!(fact.output, CharacterConstraintOutput::Return);
    let CharacterConstraintDomain::ExcludesExact { characters } = &fact.domain else {
        panic!("expected excluded-character domain: {fact:#?}");
    };
    assert!(characters.contains(&"\r".to_string()));
    assert!(characters.contains(&"\n".to_string()));
    assert!(characters.contains(&"\"".to_string()));
    assert!(characters.contains(&"\\".to_string()));
}

#[test]
fn regex_constraint_rejects_reassignment_and_reintroduced_character() {
    let reassigned = index(
        r#"
import re
_UNSAFE = re.compile(r'[\r\n]')
_UNSAFE = dynamic
def clean(value):
    return _UNSAFE.sub("_", value)
"#,
    );
    assert!(reassigned.character_constraints.is_empty());

    let reintroduced = index(
        r#"
import re
_UNSAFE = re.compile(r'[\r\n]')
def clean(value):
    return _UNSAFE.sub("\n", value)
"#,
    );
    let [fact] = reintroduced.character_constraints.as_slice() else {
        panic!(
            "expected the still-excluded CR fact: {:#?}",
            reintroduced.character_constraints
        );
    };
    assert_eq!(
        fact.domain,
        CharacterConstraintDomain::ExcludesExact {
            characters: vec!["\r".to_string()]
        },
        "a replacement that reintroduces LF must not claim LF exclusion"
    );
}

#[test]
fn same_origin_helper_requires_all_url_and_path_boundaries() {
    let exact = index(
        r#"
from urllib.parse import urlparse

def same_site(target):
    parsed = urlparse(target)
    if parsed.scheme or parsed.netloc or not target.startswith("/") or target.startswith("//"):
        return "/"
    return target
"#,
    );
    let [fact] = exact.same_origin_path_constraints.as_slice() else {
        panic!(
            "expected exact same-origin summary: {:#?}",
            exact.same_origin_path_constraints
        );
    };
    assert!(fact.rejects_scheme);
    assert!(fact.rejects_authority);
    assert!(fact.requires_absolute_path);
    assert!(fact.rejects_scheme_relative_path);

    for source in [
        r#"
from urllib.parse import urlparse
def weak(target):
    parsed = urlparse(target)
    if parsed.scheme or parsed.netloc or not target.startswith("/"):
        return "/"
    return target
"#,
        r#"
from urllib.parse import urlparse
def inverted(target):
    parsed = urlparse(target)
    if parsed.scheme or parsed.netloc or target.startswith("/") or target.startswith("//"):
        return "/"
    return target
"#,
    ] {
        let weak = index(source);
        assert!(
            weak.same_origin_path_constraints.is_empty(),
            "partial/inverted helper must fail closed: {:#?}",
            weak.same_origin_path_constraints
        );
    }
}

#[test]
fn finite_constructor_map_selection_is_a_clean_assignment_fact() {
    use bonsai_lang_api::LanguageAdapter;
    use std::sync::Arc;

    let adapter: Arc<dyn LanguageAdapter> = Arc::new(bonsai_lang_python::PythonAdapter::new());
    let ws = bonsai_testkit::workspace_with(
        vec![adapter],
        &[(
            "templates.py",
            r#"
TEMPLATES = {"welcome": Template("Hello"), "receipt": Template("Receipt")}
def choose(name):
    selected = TEMPLATES.get(name)
    return selected
"#,
        )],
    );
    let file = ws.db().vfs().all_files()[0];
    let index = ws.db().decl_index(file).expect("Python declaration index");
    let [fact] = index.finite_literal_selections.as_slice() else {
        panic!(
            "expected one finite selection: {:#?}",
            index.finite_literal_selections
        );
    };
    assert_eq!(fact.target.as_deref(), Some("selected"));
    assert!(fact.assignment_span.is_some());
}

#[test]
fn finite_map_selection_respects_scope_shadowing_and_mutation() {
    for source in [
        r#"
def define():
    choices = {"safe": "literal"}
    return choices
def use(name):
    selected = choices.get(name)
    return selected
"#,
        r#"
CHOICES = {"safe": "literal"}
def use(name, CHOICES):
    selected = CHOICES.get(name)
    return selected
"#,
        r#"
CHOICES = {"safe": "literal"}
CHOICES.update(load_dynamic_values())
def use(name):
    selected = CHOICES.get(name)
    return selected
"#,
    ] {
        let lowered = index(source);
        assert!(
            lowered.finite_literal_selections.is_empty(),
            "out-of-scope, shadowed, or mutated maps must not produce clean-selection facts: {:#?}",
            lowered.finite_literal_selections
        );
    }
}
