use std::sync::Arc;

const GUARDED_FETCH: &str = r#"package Guard;
my %APPROVED = map { $_ => 1 } qw(api.example hooks.example);
sub fetch {
    my ($input) = @_;
    my $endpoint = Endpoint->new($input);
    return '' unless $endpoint->protocol eq 'secure'
        && $APPROVED{ $endpoint->server // '' };
    my $client = Client->new(max_hops => 0);
    $client->fetch($endpoint->render);
}
1;
"#;

fn index(source: &str) -> Arc<bonsai_lang_api::DeclIndex> {
    let workspace = bonsai_testkit::workspace_with(
        vec![Arc::new(bonsai_lang_perl::PerlAdapter::new())],
        &[("Guard.pm", source)],
    );
    let file = workspace.vfs().all_files()[0];
    workspace.db().decl_index(file).expect("Perl declaration index")
}

#[test]
fn terminal_compound_static_allowlist_retains_exact_syntax_evidence() {
    let index = index(
        r#"package Guard;
my %APPROVED = map { $_ => 1 } qw(api.example hooks.example);

sub fetch {
    my ($input) = @_;
    my $endpoint = Endpoint->new($input);
    return '' unless $endpoint->protocol && $endpoint->protocol eq 'secure'
        && $APPROVED{ $endpoint->server // '' };

    my $client = Client->new(max_hops => 0);
    my $result = $client->fetch($endpoint->render);
    return $result;
}
1;
"#,
    );
    let fact = index
        .compiler_guards
        .iter()
        .find(|fact| fact.capability == "terminal-predicate.compound-static-allowlist")
        .unwrap_or_else(|| panic!("missing compiler guard: {:#?}", index.compiler_guards));
    for expected in [
        "guarded-argument:0=predicate-component:render",
        "predicate-complete:true",
        "finite-static-string-membership:true",
        "parser-call:Endpoint.new",
        "scheme-component:protocol",
        "scheme-value:string:secure",
        "membership-kind:hash-element",
        "membership-component:server",
        "receiver-factory-call:Client.new",
        "receiver-config:max_hops=boolean:false",
    ] {
        assert!(
            fact.evidence.iter().any(|evidence| evidence == expected),
            "missing {expected}: {fact:#?}"
        );
    }
}

#[test]
fn dynamic_collection_does_not_claim_complete_guard() {
    let index = index(
        r#"package Guard;
my %APPROVED = configured_hosts();
sub fetch {
    my ($input) = @_;
    my $endpoint = Endpoint->new($input);
    return '' unless $endpoint->protocol eq 'secure'
        && $APPROVED{ $endpoint->server // '' };
    my $client = Client->new(max_hops => 0);
    $client->fetch($endpoint->render);
}
1;
"#,
    );
    assert!(
        index.compiler_guards.is_empty(),
        "dynamic collection must fail closed: {:#?}",
        index.compiler_guards
    );
}

#[test]
fn compound_allowlist_requires_necessary_predicates_and_stable_bindings() {
    let baseline = index(GUARDED_FETCH);
    assert!(
        !baseline.compiler_guards.is_empty(),
        "positive fixture must prove the guard"
    );
    let mut failures = Vec::new();
    for (label, source) in [
        (
            "shared parser state",
            GUARDED_FETCH.replace("my $endpoint", "our $endpoint"),
        ),
        (
            "shared client state",
            GUARDED_FETCH.replace("my $client", "our $client"),
        ),
        ("inequality", GUARDED_FETCH.replace(" eq ", " ne ")),
        (
            "optional membership",
            GUARDED_FETCH.replace("\n        &&", "\n        ||"),
        ),
        (
            "ignored callback",
            GUARDED_FETCH
                .replace("    return '' unless", "    my $unused = sub { return '' unless")
                .replace(" // '' };", " // '' }; };"),
        ),
        (
            "conditional guard",
            GUARDED_FETCH
                .replace("    return '' unless", "    if ($input) { return '' unless")
                .replace(" // '' };", " // '' }; }"),
        ),
        (
            "map mutation",
            GUARDED_FETCH.replace("    my $endpoint", "    $APPROVED{$input} = 1;\n    my $endpoint"),
        ),
        (
            "map increment",
            GUARDED_FETCH.replace("    my $endpoint", "    ++$APPROVED{$input};\n    my $endpoint"),
        ),
        (
            "map alias escape",
            GUARDED_FETCH.replace(
                "    my $endpoint",
                "    mutate($APPROVED{$input});\n    my $endpoint",
            ),
        ),
        (
            "parser overwritten",
            GUARDED_FETCH.replace(
                "    return '' unless",
                "    $endpoint = replacement();\n    return '' unless",
            ),
        ),
        (
            "parser overwritten after guard",
            GUARDED_FETCH.replace("    my $client", "    $endpoint = replacement();\n    my $client"),
        ),
        (
            "parser mutation",
            GUARDED_FETCH.replace("    my $client", "    $endpoint->server($input);\n    my $client"),
        ),
        (
            "factory overwritten",
            GUARDED_FETCH.replace(
                "    $client->fetch",
                "    $client = replacement();\n    $client->fetch",
            ),
        ),
        (
            "duplicate config",
            GUARDED_FETCH.replace("max_hops => 0", "max_hops => 0, max_hops => 5"),
        ),
        (
            "odd config",
            GUARDED_FETCH.replace("max_hops => 0", "max_hops => 0, $input"),
        ),
        (
            "dynamic membership key",
            GUARDED_FETCH.replace("$endpoint->server // ''", "$input . $endpoint->server"),
        ),
        (
            "array interpolation",
            GUARDED_FETCH.replace("'secure'", "\"@protocols\""),
        ),
    ] {
        let lowered = index(&source);
        if !lowered.compiler_guards.is_empty() {
            failures.push(label);
        }
    }
    assert!(failures.is_empty(), "unproven complete guards: {failures:?}");
}
