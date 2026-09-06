use bonsai_lang_api::{
    CharacterClass, CharacterConstraintDomain, CharacterConstraintOutput, CharacterConstraintProof,
    LanguageAdapter,
};
use std::sync::Arc;

fn index(source: &str) -> bonsai_lang_api::DeclIndex {
    let adapter: Arc<dyn LanguageAdapter> = Arc::new(bonsai_lang_python::PythonAdapter::new());
    let ws = bonsai_testkit::workspace_with(vec![adapter], &[("guards.py", source)]);
    let file = *ws.db().vfs().all_files().first().expect("fixture file");
    (*ws.db().decl_index(file).expect("Python declaration index")).clone()
}

#[test]
fn finite_map_selection_preserves_dynamic_fallback_and_surrounding_expression() {
    for expression in [
        "choices.get(key, dynamic)",
        "choices.get(key) + dynamic",
        "transform(choices.get(key), dynamic)",
        "choices.get(*dynamic)",
        "choices.get(key, default=dynamic)",
    ] {
        let source = format!("def choose(key, dynamic):\n    choices = {{'known': 'literal'}}\n    selected = {expression}\n    return selected\n");
        let lowered = index(&source);
        assert!(
            lowered.finite_literal_selections.is_empty(),
            "the complete assigned value is not proven finite for {expression}: {:?}",
            lowered.finite_literal_selections
        );
    }
}

#[test]
fn finite_map_values_require_immutable_literal_evidence() {
    for value in [
        "read_input()",
        "Factory('literal')",
        "[]",
        "{}",
        "('literal', [])",
    ] {
        let source = format!("def choose(key):\n    choices = {{'known': {value}}}\n    selected = choices.get(key)\n    return selected\n");
        let lowered = index(&source);
        assert!(
            lowered.finite_literal_selections.is_empty(),
            "call results and mutable nested state are not proven clean constants: {value}"
        );
    }
}

#[test]
fn finite_map_selection_keeps_exact_constant_fallbacks() {
    for expression in [
        "choices.get(key)",
        "choices.get(key, 'fallback')",
        "(choices.get(key, choices['known']))",
    ] {
        let source = format!("def choose(key):\n    choices = {{'known': 'literal'}}\n    selected = {expression}\n    return selected\n");
        assert_eq!(index(&source).finite_literal_selections.len(), 1, "{expression}");
    }
}

#[test]
fn regex_guard_rejects_separator_ranges_and_unanchored_alternatives() {
    for pattern in ["^[A-z]+$", "^[.-z]+$", "^safe|name$", "^[a-z]+|[0-9]+$"] {
        let source = format!("import re\n_ALLOWED = re.compile(r'{pattern}')\ndef load(name):\n    if not _ALLOWED.match(name):\n        return None\n    return open(name)\n");
        assert!(
            index(&source).character_constraints.is_empty(),
            "{pattern} does not exclude path separators from the whole input"
        );
    }
}

#[test]
fn regex_proofs_require_complete_unshadowed_calls() {
    for source in [
        "import re\n_ALLOWED = re.compile(r'^[a-z]+$', re.MULTILINE)\ndef load(name):\n    if not _ALLOWED.match(name):\n        return None\n    return open(name)\n",
        "import re\n_ALLOWED = re.compile(r'^[a-z]+$', flags=re.MULTILINE)\ndef load(name):\n    if not _ALLOWED.match(name):\n        return None\n    return open(name)\n",
        "import re\n_ALLOWED = re.compile(r'^[a-z]+$')\ndef load(name, _ALLOWED):\n    if not _ALLOWED.match(name):\n        return None\n    return open(name)\n",
        "import re\n_UNSAFE = re.compile(r'[ab]')\ndef clean(value):\n    return _UNSAFE.sub('_', value, count=1)\n",
        "import re\n_UNSAFE = re.compile(r'[ab]')\ndef clean(value, _UNSAFE):\n    return _UNSAFE.sub('_', value)\n",
        "import re\ndef other():\n    _UNSAFE = re.compile(r'[ab]')\ndef clean(value):\n    return _UNSAFE.sub('_', value)\n",
    ] {
        assert!(index(source).character_constraints.is_empty(), "call options and lexical receiver identity cannot be discarded: {source}");
    }
}

#[test]
fn regex_substitution_requires_one_complete_character_class() {
    for pattern in ["[a][b]", "[a]|[b]", "[a]+[b]", "[[]]"] {
        let source = format!("import re\n_UNSAFE = re.compile(r'{pattern}')\ndef clean(value):\n    return _UNSAFE.sub('_', value)\n");
        assert!(
            index(&source).character_constraints.is_empty(),
            "{pattern} does not remove every occurrence of each constituent character"
        );
    }
}

#[test]
fn comprehension_allowlist_lowers_to_exact_alphabet() {
    let index = index(
        r#"
def clean(q: str):
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
    assert_eq!(fact.proof, CharacterConstraintProof::ExactRuntimeSemantics);
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
fn comprehension_constraint_records_when_source_payload_evidence_is_required() {
    let untyped = index(
        r#"
def clean(values):
    safe = "".join(ch for ch in values if ch.isalnum())
    return safe
"#,
    );
    let [fact] = untyped.character_constraints.as_slice() else {
        panic!("expected structural constraint: {untyped:#?}");
    };
    assert_eq!(
        fact.proof,
        CharacterConstraintProof::RequiresSourcePayloadEvidence
    );

    let shadowed = index(
        r#"
class str:
    pass
def clean(values: str):
    safe = "".join(ch for ch in values if ch.isalnum())
    return safe
"#,
    );
    let [shadowed_fact] = shadowed.character_constraints.as_slice() else {
        panic!("expected structural constraint: {shadowed:#?}");
    };
    assert_eq!(
        shadowed_fact.proof,
        CharacterConstraintProof::RequiresSourcePayloadEvidence
    );

    let lookalike = index(
        r#"
class Joiner:
    def join(self, values): return "safe"
def clean(values: str, joiner: Joiner):
    safe = joiner.join(ch for ch in values if ch.isalnum())
    return safe
"#,
    );
    assert!(
        lookalike.character_constraints.is_empty(),
        "lookalike join receivers must fail closed: {:#?}",
        lookalike.character_constraints
    );
}

#[test]
fn comprehension_constraint_accepts_only_branch_local_builtin_string_narrowing() {
    let narrowed = index(
        r#"
def clean(value):
    if isinstance(value, str):
        safe = "".join(ch for ch in value if ch.isalnum())
        return safe
    return ""
"#,
    );
    assert_eq!(narrowed.character_constraints.len(), 1, "{narrowed:#?}");

    for source in [
        r#"
def clean(value):
    if isinstance(value, str):
        pass
    safe = "".join(ch for ch in value if ch.isalnum())
    return safe
"#,
        r#"
class str:
    pass
def clean(value):
    if isinstance(value, str):
        safe = "".join(ch for ch in value if ch.isalnum())
        return safe
    return ""
"#,
    ] {
        let rejected = index(source);
        let [fact] = rejected.character_constraints.as_slice() else {
            panic!("expected a structural constraint without exact type proof: {rejected:#?}");
        };
        assert_eq!(
            fact.proof,
            CharacterConstraintProof::RequiresSourcePayloadEvidence,
            "out-of-scope or shadowed narrowing must not become an exact proof"
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
fn regex_provider_identity_expands_aliases_and_rejects_lexical_shadows() {
    let aliased = index(
        r#"
import re as patterns
CONTROL = patterns.compile(r'[\r\n]')
def clean(value):
    return CONTROL.sub("_", value)
"#,
    );
    let [fact] = aliased.character_constraints.as_slice() else {
        panic!(
            "expected aliased regex fact: {:#?}",
            aliased.character_constraints
        );
    };
    let CharacterConstraintDomain::ProviderBound { factory_call, .. } = &fact.domain else {
        panic!("expected provider-bound fact: {fact:#?}");
    };
    assert_eq!(factory_call, "re.compile");

    let lookalike = index(
        r#"
from text_patterns import compile
CONTROL = compile(r'[\r\n]')
def clean(value):
    return CONTROL.sub("_", value)
"#,
    );
    let [fact] = lookalike.character_constraints.as_slice() else {
        panic!(
            "expected generic provider fact: {:#?}",
            lookalike.character_constraints
        );
    };
    let CharacterConstraintDomain::ProviderBound { factory_call, .. } = &fact.domain else {
        panic!("expected provider-bound fact: {fact:#?}");
    };
    assert_eq!(factory_call, "text_patterns.compile");

    for source in [
        r#"
import re
def clean(value, re):
    control = re.compile(r'[\r\n]')
    return control.sub("_", value)
"#,
        r#"
import re
factory = choose_factory()
def clean(value):
    control = factory(r'[\r\n]')
    return control.sub("_", value)
"#,
    ] {
        let lowered = index(source);
        assert!(
            lowered.character_constraints.is_empty(),
            "lexically shadowed or dynamic factories must not acquire an imported provider: {:#?}",
            lowered.character_constraints
        );
    }
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
fn guarded_value_helper_preserves_provider_components_and_generic_predicate_polarity() {
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
    let [fact] = exact.guarded_value_constraints.as_slice() else {
        panic!(
            "expected exact same-origin summary: {:#?}",
            exact.guarded_value_constraints
        );
    };
    assert_eq!(fact.rejected_components, ["scheme", "netloc"]);
    assert!(fact.accepted_prefixes.is_empty());
    assert!(fact.rejected_prefixes.is_empty());
    assert_eq!(fact.predicate_calls.len(), 2);
    assert!(fact.predicate_calls.iter().any(|call| call.required_result));
    assert!(fact.predicate_calls.iter().any(|call| !call.required_result));
    assert_eq!(fact.static_fallbacks, ["/"]);
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
        aliased.guarded_value_constraints[0].provider_call.as_deref(),
        Some("urllib.parse.urlparse")
    );

    let split = index(
        r#"
from urllib.parse import urlsplit as parse_target
def same_site(target):
    parsed = parse_target(target)
    if parsed.scheme or parsed.netloc or not target.startswith("/") or target.startswith("//"):
        return "/"
    return target
"#,
    );
    assert_eq!(
        split.guarded_value_constraints[0].provider_call.as_deref(),
        Some("urllib.parse.urlsplit")
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
        lookalike.guarded_value_constraints[0].provider_call.as_deref(),
        Some("untrusted_url_helpers.urlparse")
    );

    for source in [
        r#"
from urllib.parse import urlparse
def same_site(target, urlparse):
    parsed = urlparse(target)
    if parsed.scheme or parsed.netloc or not target.startswith("/") or target.startswith("//"):
        return "/"
    return target
"#,
        r#"
def same_site(target, parser):
    parsed = parser(target)
    if parsed.scheme or parsed.netloc or not target.startswith("/") or target.startswith("//"):
        return "/"
    return target
"#,
    ] {
        let lowered = index(source);
        assert!(
            lowered.guarded_value_constraints.is_empty(),
            "lexically shadowed or dynamic parsers must not acquire provider identity: {:#?}",
            lowered.guarded_value_constraints
        );
    }

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
        assert_eq!(
            weak.guarded_value_constraints.len(),
            1,
            "the adapter must preserve partial constraints for rule-owned evaluation: {:#?}",
            weak.guarded_value_constraints
        );
    }
}

#[test]
fn constructor_map_selection_is_not_a_clean_literal_fact() {
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
    assert!(
        index.finite_literal_selections.is_empty(),
        "an unresolved constructor may read dynamic input; literal arguments do not prove a clean result"
    );
}

#[test]
fn finite_map_selection_rejects_same_spelled_method_without_literal_map_state() {
    let lowered = index(
        r#"
class Catalog:
    def get(self, key):
        return dynamic_value(key)

def choose(catalog: Catalog, name):
    selected = catalog.get(name)
    return selected
"#,
    );
    assert!(
        lowered.finite_literal_selections.is_empty(),
        "method spelling alone is not a finite selector: {:#?}",
        lowered.finite_literal_selections
    );
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
