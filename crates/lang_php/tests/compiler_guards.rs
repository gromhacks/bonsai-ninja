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
