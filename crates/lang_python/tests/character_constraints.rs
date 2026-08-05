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
    let CharacterConstraintDomain::ProviderBound {
        factory_call,
        operation_call,
        domain,
    } = &fact.domain
    else {
        panic!("expected provider-bound domain: {fact:#?}");
    };
    assert_eq!(factory_call, "re.compile");
    assert_eq!(operation_call, "_UNSAFE.sub");
    let CharacterConstraintDomain::ExcludesExact { characters } = domain.as_ref() else {
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
    let CharacterConstraintDomain::ProviderBound { domain, .. } = &fact.domain else {
        panic!("expected provider-bound domain: {fact:#?}");
    };
    assert_eq!(
        domain.as_ref(),
        &CharacterConstraintDomain::ExcludesExact {
            characters: vec!["\r".to_string()]
        },
        "a replacement that reintroduces LF must not claim LF exclusion"
    );
}

#[test]
fn compiled_regex_rejection_lowers_provider_bound_path_domain() {
    let lowered = index(
        r#"
import re
_NAME = re.compile(r"^[A-Za-z0-9_-]{1,64}\.(mp4|mkv|webm)$")

def load(name):
    if not _NAME.match(name):
        return None
    return open(name)
"#,
    );
    let load = lowered
        .defs
        .iter()
        .find(|decl| decl.name == "load")
        .expect("load decl");
    let facts = lowered
        .character_constraints
        .iter()
        .filter(|fact| fact.function_span == load.span)
        .collect::<Vec<_>>();
    let [fact] = facts.as_slice() else {
        panic!(
            "expected compiled regex guard fact: {:#?}",
            lowered.character_constraints
        );
    };
    assert_eq!(fact.input_place, "name");
    assert_eq!(fact.input_param_index, Some(0));
    assert_eq!(
        fact.output,
        CharacterConstraintOutput::Assignment {
            target: "name".to_string()
        }
    );
    let CharacterConstraintDomain::ProviderBound {
        factory_call,
        operation_call,
        domain,
    } = &fact.domain
    else {
        panic!("provider identity missing: {fact:#?}");
    };
    assert_eq!(factory_call, "re.compile");
    assert_eq!(operation_call, "_NAME.match");
    assert_eq!(
        domain.as_ref(),
        &CharacterConstraintDomain::ExcludesExact {
            characters: vec!["/".to_string(), "\\".to_string()]
        }
    );

    let broad = index(
        r#"
import re
_NAME = re.compile(r"^.*$")
def load(name):
    if not _NAME.match(name): return None
    return open(name)
"#,
    );
    assert!(broad.character_constraints.is_empty());
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
    assert_eq!(fact.provider_call.as_deref(), Some("urllib.parse.urlparse"));

    let aliased = index(
        r#"
import urllib.parse as parsing
def same_site(target):
    parsed = parsing.urlparse(target)
    if parsed.scheme or parsed.netloc or not target.startswith("/") or target.startswith("//"):
        return "/"
    return target
"#,
    );
    assert_eq!(
        aliased.same_origin_path_constraints[0].provider_call.as_deref(),
        Some("urllib.parse.urlparse")
    );

    let lookalike = index(
        r#"
from untrusted_url_helpers import urlparse
def same_site(target):
    parsed = urlparse(target)
    if parsed.scheme or parsed.netloc or not target.startswith("/") or target.startswith("//"):
        return "/"
    return target
"#,
    );
    assert_eq!(
        lookalike.same_origin_path_constraints[0].provider_call.as_deref(),
        Some("untrusted_url_helpers.urlparse")
    );

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
fn finite_literal_map_default_read_and_character_substitution_are_compiler_facts() {
    let lowered = index(
        r#"
_ESCAPES = {"\\": r"\5c", "*": r"\2a", "(": r"\28", ")": r"\29", "\x00": r"\00"}

def choose(name):
    providers = {"a": "https://a.example/", "b": "https://b.example/"}
    selected = providers.get(name, providers["a"])
    return selected

def escape(value):
    return "".join(_ESCAPES.get(ch, ch) for ch in (value or ""))
"#,
    );
    assert_eq!(lowered.finite_literal_selections.len(), 1);
    let [substitution] = lowered.character_substitutions.as_slice() else {
        panic!(
            "expected exact static-map substitution: {:#?}",
            lowered.character_substitutions
        );
    };
    assert_eq!(substitution.input_param_index, 0);
    assert_eq!(substitution.exact_mappings.len(), 5);
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

#[test]
fn finite_maps_keep_independent_same_spelled_callable_bindings() {
    let lowered = index(
        r#"
def choose_template(name):
    choices = {"safe": "template.html"}
    selected = choices.get(name)
    return selected

def choose_report(name):
    choices = {"safe": "report.html"}
    selected = choices.get(name)
    return selected
"#,
    );
    assert_eq!(
        lowered.finite_literal_selections.len(),
        2,
        "independent Python locals use lexical binding identity, not one file-wide spelling: {:#?}",
        lowered.finite_literal_selections
    );
}

#[test]
fn finite_module_map_tracks_cross_callable_mutation_and_local_shadowing() {
    let mutated = index(
        r#"
CHOICES = {"safe": "literal"}
def mutate():
    CHOICES.update(load_dynamic_values())
def choose(name):
    return CHOICES.get(name)
"#,
    );
    assert!(
        mutated.finite_literal_selections.is_empty(),
        "a method call through an unshadowed global binding can mutate the module map"
    );

    let shadowed = index(
        r#"
CHOICES = {"safe": "literal"}
def local_only(name):
    CHOICES = {"safe": "other"}
    selected = CHOICES.get(name)
    return selected
def choose(name):
    selected = CHOICES.get(name)
    return selected
"#,
    );
    assert_eq!(
        shadowed.finite_literal_selections.len(),
        2,
        "a local shadow neither mutates nor suppresses an independent module binding: {:#?}",
        shadowed.finite_literal_selections
    );
}

#[test]
fn finite_map_binding_owner_honors_global_and_nonlocal_directives() {
    let global_read = index(
        r#"
CHOICES = {"safe": "literal"}
def choose(name):
    global CHOICES
    selected = CHOICES.get(name)
    return selected
"#,
    );
    assert_eq!(global_read.finite_literal_selections.len(), 1);

    let nonlocal_read = index(
        r#"
def build():
    choices = {"safe": "literal"}
    def choose(name):
        nonlocal choices
        selected = choices.get(name)
        return selected
    return choose
"#,
    );
    assert_eq!(nonlocal_read.finite_literal_selections.len(), 1);

    let global_write = index(
        r#"
CHOICES = {"safe": "literal"}
def mutate():
    global CHOICES
    CHOICES = load_dynamic_values()
def choose(name):
    selected = CHOICES.get(name)
    return selected
"#,
    );
    assert!(
        global_write.finite_literal_selections.is_empty(),
        "a parsed global reassignment invalidates the module map"
    );
}

#[test]
fn character_substitution_tables_keep_independent_callable_bindings() {
    let lowered = index(
        r#"
def build_filter():
    escapes = {"*": r"\2a"}
    def escape(value):
        return "".join(escapes.get(ch, ch) for ch in value)
    return escape

def build_dn():
    escapes = {"(": r"\28"}
    def escape(value):
        return "".join(escapes.get(ch, ch) for ch in value)
    return escape
"#,
    );
    assert_eq!(
        lowered.character_substitutions.len(),
        2,
        "same-spelled transform tables in independent callables remain distinct: {:#?}",
        lowered.character_substitutions
    );
}

#[test]
fn finite_membership_conditional_is_a_compiler_fact() {
    let lowered = index(
        r#"
def choose(name):
    name = name if name in {"default", "long", "short"} else "default"
    return name
"#,
    );
    let [selection] = lowered.finite_literal_selections.as_slice() else {
        panic!(
            "expected one finite conditional selection: {:#?}",
            lowered.finite_literal_selections
        );
    };
    assert_eq!(selection.target.as_deref(), Some("name"));
    assert!(selection.assignment_span.is_some());
}

#[test]
fn immutable_map_membership_conditional_is_a_compiler_fact() {
    let lowered = index(
        r#"
_TEMPLATES = {
    "default": "Hello",
    "welcome": "Welcome",
    "receipt": "Receipt",
}

def render(name):
    safe = name if name in _TEMPLATES else "default"
    return render_template_string(_TEMPLATES[safe])
"#,
    );
    let [selection] = lowered.finite_literal_selections.as_slice() else {
        panic!(
            "expected the immutable map membership to constrain safe: {:#?}",
            lowered.finite_literal_selections
        );
    };
    assert_eq!(selection.target.as_deref(), Some("safe"));
    assert!(selection.assignment_span.is_some());
}

#[test]
fn finite_membership_conditional_rejects_unproven_variants() {
    for source in [
        r#"
def choose(name, other):
    name = other if name in {"default", "long"} else "default"
    return name
"#,
        r#"
def choose(name):
    name = name if name not in {"default", "long"} else "default"
    return name
"#,
        r#"
def choose(name):
    name = name if name in {"default", dynamic()} else "default"
    return name
"#,
        r#"
_TEMPLATES = {"default": "Hello", "welcome": "Welcome"}
_TEMPLATES[dynamic()] = dynamic()
def choose(name):
    return name if name in _TEMPLATES else "default"
"#,
        r#"
_TEMPLATES = {"default": "Hello", "welcome": "Welcome"}
def choose(name, _TEMPLATES):
    return name if name in _TEMPLATES else "default"
"#,
    ] {
        let lowered = index(source);
        assert!(
            lowered.finite_literal_selections.is_empty(),
            "unproven conditional must not emit a clean-selection fact: {:#?}",
            lowered.finite_literal_selections
        );
    }
}
