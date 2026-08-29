use std::sync::Arc;

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
