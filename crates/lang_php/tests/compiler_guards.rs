use bonsai_db::AnalyzerDb;
use bonsai_lang_api::LanguageRegistry;
use bonsai_lang_php::PhpAdapter;
use bonsai_vfs::Vfs;
use std::sync::Arc;

fn index(source: &str) -> Arc<bonsai_lang_api::DeclIndex> {
    let vfs = Arc::new(Vfs::new());
    let file = vfs.write("guard.php".to_string(), Arc::<str>::from(source));
    let registry = Arc::new(LanguageRegistry::new());
    registry.register(Arc::new(PhpAdapter::new()));
    let db = AnalyzerDb::new(vfs, registry);
    db.decl_index(file).expect("PHP declaration index")
}

#[test]
fn terminal_compound_static_allowlist_retains_exact_syntax_evidence() {
    let index = index(
        r#"<?php
final class Gateway {
    private const APPROVED = ['api.example', 'hooks.example'];
    public static function fetch(string $input): void {
        $parsed = split_endpoint($input);
        if (($parsed['protocol'] ?? '') !== 'secure'
            || !member_of($parsed['server'] ?? '', self::APPROVED, true)) {
            return;
        }
        configure($handle, TARGET, $input);
        configure($handle, REDIRECTS, false);
    }
}
"#,
    );
    let fact = index
        .compiler_guards
        .iter()
        .find(|fact| fact.capability == "terminal-predicate.compound-static-allowlist")
        .unwrap_or_else(|| panic!("missing compiler guard: {:#?}", index.compiler_guards));
    for expected in [
        "guarded-argument:2=predicate-argument:0",
        "predicate-complete:true",
        "finite-static-string-membership:true",
        "parser-call:split_endpoint",
        "scheme-component:protocol",
        "scheme-value:string:secure",
        "membership-call:member_of",
        "membership-component:server",
        "membership-argument:2=boolean:true",
        "related-call:configure:argument:0=guarded-argument:0",
        "related-call:configure:argument:1=place:REDIRECTS",
        "related-call:configure:argument:2=boolean:false",
    ] {
        assert!(
            fact.evidence.iter().any(|evidence| evidence == expected),
            "missing {expected}: {fact:#?}"
        );
    }
}

#[test]
fn dynamic_collection_and_nonterminal_rejection_do_not_claim_complete_guard() {
    for source in [
        r#"<?php
function fetch(string $input, array $approved): void {
    $parsed = split_endpoint($input);
    if (($parsed['protocol'] ?? '') !== 'secure'
        || !member_of($parsed['server'] ?? '', $approved, true)) {
        audit($input);
    }
    configure($handle, TARGET, $input);
}
"#,
        r#"<?php
function fetch(string $input): void {
    $parsed = split_endpoint($input);
    if (($parsed['protocol'] ?? '') !== 'secure') { return; }
    configure($handle, TARGET, $input);
}
"#,
    ] {
        let index = index(source);
        assert!(
            index.compiler_guards.is_empty(),
            "unsupported predicate must fail closed: {:#?}",
            index.compiler_guards
        );
    }
}

const COMPOUND_GUARD: &str = r#"<?php
class Gateway {
    private const APPROVED = ['api.example', 'hooks.example'];
    public static function fetch(string $input): void {
        $parsed = split_endpoint($input);
        if (($parsed['protocol'] ?? '') !== 'secure'
            || !member_of($parsed['server'] ?? '', self::APPROVED, true)) {
            return;
        }
        configure($handle, TARGET, $input);
        configure($handle, REDIRECTS, false);
        consume($handle);
    }
}
"#;

fn has_complete_guard(source: &str) -> bool {
    index(source).compiler_guards.iter().any(|fact| {
        [
            "guarded-argument:2=predicate-argument:0",
            "scheme-value:string:secure",
            "membership-argument:2=boolean:true",
            "related-call:configure:argument:0=guarded-argument:0",
            "related-call:configure:argument:1=place:REDIRECTS",
            "related-call:configure:argument:2=boolean:false",
        ]
        .iter()
        .all(|required| fact.evidence.iter().any(|evidence| evidence == *required))
    })
}

#[test]
fn compound_guard_requires_exact_polarity_scope_and_execution_order() {
    assert!(has_complete_guard(COMPOUND_GUARD));
    let mut incorrectly_proven = Vec::new();
    for (label, before, after) in [
        ("inverted comparison", "!== 'secure'", "=== 'secure'"),
        ("loose comparison", "!== 'secure'", "!= 'secure'"),
        (
            "accepted missing protocol",
            "['protocol'] ?? ''",
            "['protocol'] ?? 'secure'",
        ),
        (
            "accepted missing server",
            "['server'] ?? ''",
            "['server'] ?? 'api.example'",
        ),
        (
            "unrelated projection",
            "($parsed['protocol'] ?? '')",
            "other($parsed['protocol'] ?? '')",
        ),
        (
            "input overwrite",
            "configure($handle, TARGET",
            "$input = source(); configure($handle, TARGET",
        ),
        ("parsed overwrite", "if (($parsed", "$parsed = []; if (($parsed"),
        ("optional guard", "if (($parsed", "if ($enabled) if (($parsed"),
        (
            "else overwrite",
            "return;\n        }",
            "return;\n        } else { $input = source(); }",
        ),
        ("late bound constant", "self::APPROVED", "static::APPROVED"),
        ("wrong class constant", "self::APPROVED", "Other::APPROVED"),
        (
            "key is not value",
            "['api.example', 'hooks.example']",
            "['api.example' => DYNAMIC]",
        ),
        (
            "named argument",
            "self::APPROVED, true",
            "self::APPROVED, strict: true",
        ),
        (
            "spread argument",
            "self::APPROVED, true",
            "self::APPROVED, ...$options",
        ),
        (
            "conditional configuration",
            "configure($handle, REDIRECTS",
            "if ($enabled) configure($handle, REDIRECTS",
        ),
        (
            "late configuration",
            "configure($handle, REDIRECTS",
            "consume($handle); configure($handle, REDIRECTS",
        ),
        (
            "wrong configured receiver",
            "configure($handle, REDIRECTS",
            "configure($other, REDIRECTS",
        ),
        (
            "conflicting later configuration",
            "consume($handle);",
            "configure($handle, REDIRECTS, true); consume($handle);",
        ),
        (
            "conditional later configuration",
            "consume($handle);",
            "if ($enabled) configure($handle, REDIRECTS, true); consume($handle);",
        ),
        (
            "mixed argument evidence",
            "configure($handle, REDIRECTS, false);",
            "configure($handle, REDIRECTS, true); configure($other, UNUSED, false);",
        ),
    ] {
        assert!(COMPOUND_GUARD.contains(before), "bad test fixture: {label}");
        if has_complete_guard(&COMPOUND_GUARD.replace(before, after)) {
            incorrectly_proven.push(label);
        }
    }
    assert!(
        incorrectly_proven.is_empty(),
        "invalid proofs: {incorrectly_proven:?}"
    );
}

#[test]
fn same_named_constant_in_another_class_cannot_supply_collection_values() {
    let source = COMPOUND_GUARD.replace("['api.example', 'hooks.example']", "DYNAMIC")
        + "\nclass Other { private const APPROVED = ['api.example']; }\n";
    assert!(!has_complete_guard(&source));
}

#[test]
fn exact_direct_projections_and_parentheses_keep_valid_guard_evidence() {
    let source = COMPOUND_GUARD
        .replace("($parsed['protocol'] ?? '')", "(($parsed['protocol']))")
        .replace("$parsed['server'] ?? ''", "($parsed['server'])");
    assert!(has_complete_guard(&source));
}
